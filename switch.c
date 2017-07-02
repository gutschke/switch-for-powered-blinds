// TODO
// Deal more gracefully with multiple button presses
// See if we can poll the blinds even more gently, as they have a habit of
//   crashing easily and then becoming inresponsive.

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/in.h>
#include <poll.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#ifdef WIRING
#include <wiringPi.h>
#endif
#include <unistd.h>

#include "jsmn/jsmn.h"


// GPIO pin numbers for up and down button.
static const int UP              = 7;
static const int DOWN            = 1;

// Number of milliseconds to wait for buttons to debounce.
static const int DEBOUNCE        = 8;

// Number of milliseconds to wait between polling buttons.
static const int SLEEP           = 15;
static const int DEEP_SLEEP      = 100;

// Base URL of the Hunter Douglas PowerView controller
static const char URL[]          = "http://windowblinds/api";

// Number of seconds to wait before polling the controller for any changes.
#ifdef NDEBUG
static const int DEFAULT_TIMEOUT = 900;
#else
static const int DEFAULT_TIMEOUT = 30;
#endif
static const int SHORT_TIMEOUT   = 10;
static const int RESPONSE_TIMEOUT= 60;

// If the user keeps smashing the button and reaches the end of the list of scenes,
// there needs to be at least this many seconds of inactivity before we again try to
// set the very last (or first) scene.
static const int REPEAT_TIMEOUT  = 5;

// Try to keep HTTP connection open across requests.
static char *cachedHost;
static int  cachedSocket         = -1;

// The room where the button is located
static const char ROOM[]         = "Living Room Darkening & Black Out";


// Convert to/from base-relative addressing, which keeps pointers intact,
// even if they point into a memory block that gets moved by realloc()
#define TOBASEREL(base, ptr)   ((typeof(ptr))((char *)ptr - (char *)base))
#define FROMBASEREL(base, ptr) ((typeof(ptr))((ptrdiff_t)ptr + (char *)base))


// Common helper macros
#define ARRAY_SIZE(A) _Generic(&(A), typeof((A)[0]) **: (void)0,        \
                               default: sizeof(A) / sizeof((A)[0]))
#define max(a, b) ({ typeof(a) _a = (a); typeof(b) _b = (b); _a>_b ? _a : _b; })
#ifndef NDEBUG
#define debug(args...) printf(args)
#else
#define debug(args...) do { if (0) { printf(args); } } while (0)
#endif


// Reverses Base64 encoding for one character. Supports both the standard
// alphabet and the modified alphabet used by the Hunter Douglas controller
// (it replaces "/" with "@").
static char base64Byte(char ch) {
  if      (ch >= 'A' && ch <= 'Z') return(ch - 'A');
  else if (ch >= 'a' && ch <= 'z') return(ch - 'a' + 26);
  else if (ch >= '0' && ch <= '9') return(ch - '0' + 52);
  else if (ch == '+')              return(62);
  else                             return(63);
}

// Decodes a Base64 encoded input string of length "len" bytes. Always
// appends a terminating NUL, but doesn't include the terminator in the
// returned number of bytes written.
// Source and destination buffers must not overlap.
static size_t base64Decode(const char *src, char *dst, ssize_t len) {
  if (len > 0 && src[len-1] == '=') len--;
  if (len > 0 && src[len-1] == '=') len--;
  char *to = dst;
  for (const char *from = src; len > 1; len -= 4, from += 4) {
    switch (len) {
    default: to[2] = (base64Byte(from[2])<<6) +   base64Byte(from[3]);
    case 3:  to[1] = (base64Byte(from[1])<<4) +  (base64Byte(from[2])      >>2);
    case 2:  to[0] = (base64Byte(from[0])<<2) + ((base64Byte(from[1])&0x30)>>4);
    }
    to += len >= 4 ? 3 : len - 1;
  }
  *to = '\0';
  return to - dst;
}


// Reads from a file descriptor with a timeout (in seconds). In case of
// timeout or unexpected error, returns "0" indicating an end-of-file condition.
static ssize_t readWithTimeout(int fd, char *buf, size_t len, int timeout) {
  struct pollfd pfd = { .fd = fd, .events = POLLIN };
  int rc = poll(&pfd, 1, timeout * 1000);
  if (rc <= 0) {
    return rc;
  }
  if (pfd.revents & POLLIN) {
    return read(fd, buf, len);
  }
  return 0;
}


// Retrieve HTTP connection from cache. It might or might not still be open,
// depending on whether the server closed it after a timeout.
static int getFromCache(const char *url, size_t len) {
  if (cachedHost && strlen(cachedHost) == len &&
      !memcmp(cachedHost, url, len)) {
    return cachedSocket;
  }
  return -1;
}


// Store connection in cache. Setting the "url" to NULL clears the cache.
static void destroyCache();
static void storeInCache(const char *url, size_t len, int fd) {
  static int initialized = 0;
  if (!initialized) {
    initialized = 1;
    atexit(destroyCache);
  }

  // Check if we are storing the same entry that already is in the cache.
  if (cachedHost && url && len > 0 && strlen(cachedHost) == len &&
      !memcmp(cachedHost, url, len) && fd >= 0) {
    // Did the file descriptor change?
    if (fd != cachedSocket) {
      if (cachedSocket >= 0) {
        close(cachedSocket);
      }
      cachedSocket = fd;
    }
    return;
  }
  // Remove any old data from the cache.
  free(cachedHost);
  cachedHost = NULL;
  if (cachedSocket >= 0) {
    close(cachedSocket);
    cachedSocket = -1;
  }
  // Add an entirely new entry to the cache.
  if (url && len > 0 && fd >= 0) {
    memcpy(cachedHost = calloc(len + 1, 1), url, len);
    cachedSocket = fd;
  }
  return;
}


// Turns out, the cached socket has become invalid. This most likely
// is the result of the other end closing it after a timeout.
static void invalidateCache() {
  if (cachedSocket >= 0) {
    close(cachedSocket);
  }
  cachedSocket = -1;
  return;
}


// Destroy all data in the cache and close any file descriptors that
// might still be open.
static void destroyCache() {
  storeInCache(NULL, 0, -1);
  return;
}


// Open a TCP socket to connect to the given URL. If the connection was
// cached, the "retCached" variable is set accordingly.
static int getSocket(const char *url, int *retCached) {
  // Fill the return variables with sane defaults, if we happen to exit
  // early.
  if (retCached) *retCached = 0;

  // The function gradually starts filling up the following variables with
  // data. The exit handler "err" cleans up any temporary resources.
  char *service = NULL, *hostname = NULL;
  int fd = -1, ret = -1;
  struct addrinfo *addressInfo = NULL;

  // Extract service (i.e. "http") and hostname from URL.
  const char *ptr = strstr(url, "://");
  if (!ptr) goto err;
  size_t serviceLength = ptr - url;
  size_t hostnameLength = strcspn(ptr+3, "/");

  // Cache one open connection.
  fd = getFromCache(url, serviceLength + hostnameLength + 3);
  if (fd >= 0) {
    if (retCached) *retCached = 1;
    ret = fd;
    goto err;
  }

  // Create new NUL-terminated temporary strings.
  service = memcpy(calloc(serviceLength+1, 1), url, serviceLength);
  hostname = memcpy(calloc(hostnameLength+1, 1), ptr+3, hostnameLength);

  // Perform DNS lookup to determine IPv4 or IPv6 internet address.
  const struct addrinfo hints = { .ai_socktype = SOCK_STREAM };
  if (getaddrinfo(hostname, service, &hints, &addressInfo)) goto err;
  for (const struct addrinfo *entry = addressInfo;
       entry; entry = entry->ai_next) {
    // Try to open socket.
    fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
    if (fd < 0) goto err;
    if (connect(fd, entry->ai_addr, entry->ai_addrlen) == 0) {
      // We successfully opened a socket and can return it.
      ret = fd;
      break;
    }
    close(fd);
  }
err:
  // Clean up temporary resources.
  if (addressInfo) freeaddrinfo(addressInfo);
  free(service);
  free(hostname);
  if (fd >= 0 && ret < 0) close(fd);
  if (ret >= 0) storeInCache(url, serviceLength + hostnameLength + 3, ret);
  return ret;
}


// Given a "verb" and "url + path", perform a HTTP request. The status
// code of the HTTP transaction is in the return code, and response
// header and body will be returned in "retHeader" and "retBody", if
// these return variables are non-NULL.
// For "PUT" and "POST" requests, the payload can be passed in through
// "retHeader" and "retBody" as well. Callers should *not* set
// "Content-Length".
static int request(const char *verb, const char *url, const char *path,
                   int mayCache, char **retHeader, char **retBody) {
  char *postHeader = retHeader && *retHeader ? *retHeader : "";
  char *postBody = retBody && *retBody ? *retBody : "";

  static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
  pthread_mutex_lock(&mutex);

  int fd = -1, isDiskFile = 0;
  char fname[strlen(path) + 40]; *fname = '\000';
  if (mayCache && strcmp(verb, "PUT") && strcmp(verb, "POST")) {
    sprintf(fname, ".cache/%s", path + (*path == '/'));
    for (char *ptr = fname + sizeof(".cache");
         (ptr = strchr(ptr, '/')) != NULL;
         *ptr = '.') { }
    fd = open(fname, O_RDONLY);
    if (fd >= 0) {
      mayCache = 0;
      isDiskFile = 1;
    }
  }

 again:
  // Fill the return variables with sane defaults, if we happen to exit
  // early.
  if (retHeader) *retHeader = NULL;
  if (retBody)   *retBody   = NULL;

  // The function gradually starts filling up the following variables with
  // data. The exit handler "err" cleans up any temporary resources.
  char *hostname = NULL, *status = NULL, *response = NULL, *header = NULL, *ptr;
  int ret = -1;

  // Open socket to the server.
  int cached = 0;
  if (fd < 0) {
    fd = getSocket(url, &cached);
    if (fd < 0) goto err;

    // Extract hostname and remainder of URL from "url" parameter.
    ptr = strstr(url, "://");
    if (!ptr) goto err;
    size_t hostnameLength = strcspn(ptr+3, "/");
    hostname = memcpy(calloc(hostnameLength+1, 1), ptr+3, hostnameLength);
    ptr += 3 + hostnameLength;
    if (!*ptr) ptr = "/";

    // Send request.
    if (strcmp(verb, "PUT") && strcmp(verb, "POST")) {
      postBody = "";
    }
    long contentLength = strlen(postBody);
    dprintf(fd,
            "%s %s%s HTTP/1.1\r\n"
            "Host: %s\r\n"
            "Content-Type: application/json\r\n"
            "Content-Length: %ld\r\n"
            "%s"
            "\r\n"
            "%.*s",
            verb, ptr, path, hostname, contentLength, postHeader,
            (int)contentLength, postBody);
  }

  // Read response. This could be just a status code, or it could be
  // a HTTP header, possibly followed by a body.
  size_t responseLength = 0;
  long contentLength = -1;
  for (size_t allocated = 0; contentLength; ) {
    // If we don't know the content length yet, dynamically grow the
    // input buffer.
    if (contentLength == -1 && allocated - responseLength < 1024) {
      ptr = realloc(response, allocated += 4096);
      if (!ptr) goto err;
      if (!response) *ptr = '\000';
      response = ptr;
    }
    // Read whatever data is available so far.
    ssize_t bytes = readWithTimeout(fd, response + responseLength,
                                    allocated - responseLength - 1,
                                    RESPONSE_TIMEOUT);

    // If we reached the end of file, something either went wrong, or the server
    // did not provide a content length.
    if (bytes <= 0) {
      if (contentLength != -1) goto err;
      if (cached && !status && !header && responseLength == 0) {
        // Maybe a cached connection was closed on us. Try opening a
        // new one. Since we are invalidating the cache first, we retry at
        // most once.
        fd = -1;
        invalidateCache();
        free(hostname);
        free(response);
        goto again;
      }
      if (!status) {
        status = response;
        response = NULL;
      } else if (!header) {
        header = response;
        response = NULL;
      }
      break;
    }
    // Update the response buffer to reflect the successfully read data.
    responseLength += bytes;
    response[responseLength] = '\000';

    // Update the remaining number of content bytes that we are still expecting.
    if (contentLength != -1) {
      contentLength -= bytes;
      continue;
    }
    if (!status) {
      if ((ptr = strstr(response, "\r\n")) != NULL) {
        // We read the status code. Copy it into its own variable.
        size_t statusLength = ptr + 2 - response;
        status = calloc(statusLength + 1, 1);
        memcpy(status, response, statusLength);
        memmove(response, ptr + 2, responseLength - statusLength + 1);
        responseLength -= statusLength;
      }
    }
    if (status && (ptr = strstr(response, "\r\n\r\n")) != NULL) {
      // We successfully read the HTTP header. Copy it into its own variable and
      // remove if from the response buffer.
      size_t headerLength = ptr + 2 - response;
      header = calloc(headerLength + 1, 1);
      memcpy(header, response, headerLength);
      memmove(response, ptr + 4, responseLength - (headerLength + 2) + 1);
      responseLength -= headerLength + 2;

      // Check whether the HTTP header reports a content length. That's
      // preferable, as we can then read exactly as much as we need and keep
      // the connection open afterwards.
      static const char key[] = "\r\ncontent-length:";
      ptr = strcasestr(header, key);
      if (ptr) {
        const char *num = ptr + sizeof(key) - 1;
        errno = 0;
        contentLength = strtol(num, &ptr, 10);
        // Sanity check the data that was read.
        if (!ptr || ptr <= num || !isspace(*ptr) || errno) {
          contentLength = -1;
        } else {
          // If the content length is known, the reponse buffer can be resized
          // to match exactly.
          if (allocated != contentLength + 1) {
            ptr = realloc(response, allocated = contentLength + 1);
            if (!ptr) goto err;
            response = ptr;
          }
          if (responseLength > contentLength) {
            goto err;
          }
          contentLength -= responseLength;
        }
      }
    }
  }

  // By this point, the entire response from the server has been read. A
  // NUL-terminated copy of the HTTP status can be found in "status", a copy of
  // the header in "header" and a copy of the body in "response". Return this
  // data to the caller.
  if (status) {
    // If we hadn't cached this particular static file, yet. Now is a good time
    // to do so. We only ever write the file once, and then always read from it.
    // This allows us to manually edit files in order to fix bogus data. If you
    // do so, remember to update the "Content-Length", or things will go wrong
    // badly.
    if (mayCache) {
      mkdir(".cache", 0777);
      int outFd = creat(fname, 0666);
      if (outFd >= 0) {
        dprintf(outFd, "%s%s\r\n%s", status, header, response);
        close(outFd);
      }
    }

    // Fill out any return data that the caller requested.
    int code = -1;
    if (sscanf(status, "HTTP/%*d.%*d %d", &code) == 1) {
      ret = code;
    }
    if (ret >= 0) {
      if (retHeader && header) {
        *retHeader = header;
        header = NULL;
      }
      if (retBody && response) {
        *retBody = response;
        response = NULL;
      }
    }
  }

 err:
  // Clean up any temporarily allocated resources. Notably, do not close the
  // file descriptor unless it refers to an on-disk cache file. We always try
  // to reuse connections, if possible. Socket file descriptors are owned by
  // the socket cache and must be closed through cache operations.
  pthread_mutex_unlock(&mutex);
  if (isDiskFile && fd >= 0) {
    close(fd);
  }
  free(response);
  free(status);
  free(header);
  free(hostname);
  return ret;
}


// Tokenize JSON and then parse it into a tree structure.
static jsmntok_t *parseJSON(const char *json) {
  // Invoke the Jasmine JSON parser. This could take a few tries as we
  // are determining the number of tokens in the JSON input data.
  jsmn_parser parser;
  jsmn_init(&parser);
  jsmntok_t *tokens = NULL;
  int numTokens;
  for (int allocTokens = 0;;) {
    tokens = realloc(tokens, sizeof(jsmntok_t) * (allocTokens += 100));
    numTokens = jsmn_parse(&parser, json, strlen(json), tokens, allocTokens);
    if (numTokens != JSMN_ERROR_NOMEM) {
      break;
    }
  }

  // If the input data didn't parse a JSON, return an error.
  if (numTokens <= 0) {
    free(tokens);
    return NULL;
  }

  return tokens;
}


// Retrieve a JSON value.
static int getJSONValue(const char *data, const jsmntok_t *json, int idx,
                        const char *path) {
  while (idx != -1) {
    switch (*path) {
      case '\000':
        return idx;
      case '[':
        errno = 0;
        int i = strtol(path + 1, (char **)&path, 10);
        if (errno || !path || *path != ']' || i < 0) {
          return -1;
        }
        ++path;
        idx = json[idx].first_child;
        for (int j = 0; idx != -1 && j < i; ++j) {
          idx = json[idx].next;
        }
        break;
      case '.':
        ++path;
      default:;
        int len = strcspn(path, "[.");
        int type = json[idx].type;
        idx = json[idx].first_child;
        while (idx != -1) {
          if (json[idx].end - json[idx].start == len &&
              !memcmp(data + json[idx].start, path, len)) {
            path += len;
            break;
          }
          idx = json[idx].next;
        }
        if (idx != -1 && type == JSMN_OBJECT) {
          ++idx;
        }
        break;
    }
  }
  return idx;
}


// Retrieve a JSON integer value. Returns -1 on error.
static int getJSONInt(const char *data, const jsmntok_t *json, int idx,
                      const char *field) {
  int ret = getJSONValue(data, json, idx, field);
  errno = 0;
  if (ret == -1 || json[ret].type != JSMN_PRIMITIVE ||
      ((ret = strtol(data + json[ret].start, NULL, 10)), errno))
    return -1;
  return ret;
}


// Retrieve a JSON boolean value. Returns -1 on error.
static int getJSONBool(const char *data, const jsmntok_t *json, int idx,
                       const char *field) {
  int ret = getJSONValue(data, json, idx, field);
  if (ret < 0 || json[ret].type != JSMN_PRIMITIVE) {
    return -1;
  } else if (!memcmp(data + json[ret].start, "true", 4)) {
    return 1;
  } else if (!memcmp(data + json[ret].start, "false", 5)) {
    return 0;
  } else
    return -1;
}


// Retrieve and parse a UTC timestamp from JSON and convert it to number of
// seconds since the start of the epoch. Returns -1 on error. Does not account
// for leap seconds. Fails reporting accurately in the year 2200.
static int64_t getJSONUTC(const char *data, const jsmntok_t *json, int idx,
                          const char *field) {
  int64_t ret = getJSONValue(data, json, idx, field);
  if (ret < 0 || json[ret].type != JSMN_STRING ||
      json[ret].end - json[ret].start != 20) {
    return -1;
  }
  int year = -1, month = -1, day = -1, hour = -1, minute = -1;
  int second = -1, chars = -1;
  if (sscanf(data + json[ret].start, "%04u-%02u-%02uT%02u:%02u:%02uZ%n",
             &year, &month, &day, &hour, &minute, &second, &chars) != 6 ||
      chars != 20 ||
      year < 2017 || month < 1 || month > 12 || day < 1 || day > 31 ||
      hour < 0 || hour > 23 || minute < 0 || minute > 59 ||
      second < 0 || second > 59) {
    return -1;
  }
  const static int monthDays[] = { 0,31,59,90,120,151,181,212,243,273,304,334 };
  ret = (((((year - 1970)*365) + monthDays[month-1] + day - 1)*24 + hour)*60 +
         minute)*60 + second +
        ((year - 1968)/4 - (year >= 2100) - (!(year%4) && month <= 2))*86400;
  return ret;
}


// Retrieve a full dump of the controllers internal memory state. This code
// is only here for debugging purposes.
static char *getMemoryDump() __attribute__((unused));
static char *getMemoryDump(size_t *len) {
  char *mem = NULL;
  size_t memoryLen = 0;
  int startAddress = 0;

  for (int complete = 0; !complete;) {
    char *body = NULL;
    char buf[80];
    sprintf(buf, "/backup/startaddress=%d", startAddress);
    if (request("GET", URL, buf, 0, NULL, &body) == 200 && body) {
      jsmntok_t *json = parseJSON(body);
      int blobs = getJSONValue(body, json, 0, "backup.dataBlobs");
      if (blobs != -1 && json[blobs].type == JSMN_ARRAY) {
        for (int blob = json[blobs].first_child; blob != -1;
             blob = json[blob].next) {
          int size = getJSONInt(body, json, blob, "dataLength");
          int start = getJSONInt(body, json, blob, "startAddress");
          int data = getJSONValue(body, json, blob, "base64EncodedData");
          if (size < 0 || start < 0 || data < 0 ||
              json[data].type != JSMN_STRING) {
            debug("Corrupted backup data\n");
            continue;
          }
          if (start + size > memoryLen) {
            mem = realloc(mem, start + size + 1);
            mem[start + size] = '\000';
            if (start > memoryLen) {
              memset(mem + memoryLen, 0, start - memoryLen);
            }
            memoryLen = start + size;
          }
          if (json[data].end - json[data].start ==
              getJSONInt(body, json, blob, "encodedDataLength") &&
              max(0, (json[data].end - json[data].start)*3/4 - size) < 3) {
            char tmp = mem[start + size];
            if (base64Decode(body + json[data].start, mem + start,
                             json[data].end - json[data].start) != size) {
              debug("Oops. I just corrupted my own memory\n");
            }
            mem[start + size] = tmp;
          } else {
            debug("Unexpected blob size\n");
          }
        }
      }
      complete = getJSONBool(body, json, 0, "backup.dataComplete");
      startAddress = getJSONInt(body, json, 0, "backup.nextStartAddress");
      free(json);
    }
    free(body);
  }

  if (len) {
    *len = memoryLen;
  }
  return mem;
}

// Data structures defining the objects that the Hunter Douglas
// Powerview controller knows about.
struct shade {
  char *name;
  int  id;
  int  scenemember;
  int  type;     // 1 (transparent), 5 (black out)
  int  position; // 65535 (UP) .. 0 (DOWN)
};

struct scene {
  char         *name;
  struct shade *shades;
  int          numShades;
  int          id;
};


// Given the name of a room, find the number that the Hunter Douglas
// Powerview controller internally assigns to this room.
static int getRoomId(const char *room) {
  int roomNumber = -1;
  char *body;
  if (request("GET", URL, "/rooms", 1, NULL, &body) == 200 && body) {
    jsmntok_t *json = parseJSON(body);
    int roomData = getJSONValue(body, json, 0, "roomData");
    if (roomData >= 0 && json[roomData].type == JSMN_ARRAY) {
      for (int idx = json[roomData].first_child; idx != -1;
           idx = json[idx].next) {
        int name = getJSONValue(body, json, idx, "name");
        if (name == -1)
          continue;
        char nameBuf[json[name].end - json[name].start + 1];
        base64Decode(body + json[name].start, nameBuf,
                     json[name].end - json[name].start);
        if (!strcmp(nameBuf, room)) {
          if ((roomNumber = getJSONInt(body, json, idx, "id")) < 0)
            continue;
          break;
        }
      }
    }
    free(json);
    free(body);
  }
  return roomNumber;
}


// Make a best effort to retrieve the current position of the shade.
// Sometimes, this data is not available, though and the function
// returns -1.
// By asking for an explicit refresh of the reading, waiting, and
// retrying, we *usually* get an accurate result (in the range
// 0..65535). But despite our best efforts, occasionally we retrieve
// stale and seemingly arbitrary readings. And unfortunately, we do
// not have any way of telling when that happened.
static int getShadePosition(int shadeId) {
  debug("Shade "); fflush(stdout);
  int position = -1;
  char path[80];
  sprintf(path, "/shades/%d?refresh=true", shadeId);
  request("GET", URL, path, 0, NULL, NULL);
  poll(NULL, 0, 5000);
  for (int retry = 2; retry-- > 0; ) {
    char *body;
    if (request("GET", URL, path, 0, NULL, &body) == 200 && body) {
      jsmntok_t *json = parseJSON(body);
      position = getJSONInt(body, json, 0, "shade.positions.position1");

      if (position >= 0 || !retry) {
        char nameBuf[80] = "UNKNOWN", posBuf[80] = "INDETERMINATE";
        int name = getJSONValue(body, json, 0, "shade.name");
        if (name >= 0) {
          base64Decode(body + json[name].start, nameBuf,
                       json[name].end - json[name].start);
        }
        if (position >= 0 || position <= 65535) {
          if (position == 65535) {
            strcpy(posBuf, "UP");
          } else if (position == 0) {
            strcpy(posBuf, "DOWN");
          } else
            sprintf(posBuf, "at %d%% darkening (%d)",
                    100 - ((100*position + 32767) >> 16), position);
        }
        int type = getJSONInt(body, json, 0, "shade.type");
        debug("%s (%s) is %s\n", nameBuf,
              type == 1 ? "transparent" : "black out", posBuf);
      }

      free(json);
      free(body);
      if (position >= 0)
        break;
    } else {
      free(body);
    }
  }
  return position;
}


// Get a list of all of the scenes that are associated with a particular
// room. This operation heavily relies on using cached data, as the controller
// is very unreliable in accurately reporting desired shade positions for
// scene descriptions. Even after forced refreshes, the data is frequently
// incorrect. It is possible that this data would only be available after
// physically moving the shades and waiting for them to settle. As that is
// obviously not useful, it is recommended that after the first time this
// code has been run, to manually review and correct the cache files.
static struct scene *getScenes(int roomId, int *numScenes) {
  if (numScenes) {
    *numScenes = 0;
  }
  int sceneCount = 0;
  char *body;
  struct scene *ret = NULL;
  if (request("GET", URL, "/scenes", 1, NULL, &body) == 200 && body) {
    jsmntok_t *json = parseJSON(body);
    int sceneData = getJSONValue(body, json, 0, "sceneData");
    if (sceneData >= 0 && json[sceneData].type == JSMN_ARRAY) {
      for (int idx = json[sceneData].first_child; idx != -1;
           idx = json[idx].next) {
        int room = getJSONValue(body, json, idx, "roomId");
        // Filter for the desired room id number.
        if (room == -1 || strtol(body + json[room].start, NULL, 10) != roomId)
          continue;
        // Collect scene names and id numbers.
        int id = getJSONInt(body, json, idx, "id");
        int name = getJSONValue(body, json, idx, "name");
        if (id < 0 || name == -1 || json[name].type != JSMN_STRING)
          continue;
        ret = realloc(ret, sizeof(struct scene)*++sceneCount);
        memset(ret + sceneCount - 1, 0, sizeof(struct scene));
        ret[sceneCount-1].name = malloc(json[name].end - json[name].start + 1);
        base64Decode(body + json[name].start, ret[sceneCount-1].name,
                     json[name].end - json[name].start);
        ret[sceneCount-1].id = id;
      }
    }
    free(json); json = NULL;
    free(body); body = NULL;
    if (!sceneCount)
      return NULL;

    // Iterate over all the scenes in this room, and request information
    // about the shades and their desired positions.
    for (int i = sceneCount; i-- > 0; ) {
      char path[80];
      sprintf(path, "/shades?sceneId=%d", ret[i].id);
      if (request("GET", URL, path, 1, NULL, &body) == 200 &&
          body != NULL) {
        json = parseJSON(body);
        int shadeData = getJSONValue(body, json, 0, "shadeData");
        if (shadeData >= 0 && json[shadeData].type == JSMN_ARRAY) {
          for (int idx = json[shadeData].first_child; idx != -1;
               idx = json[idx].next) {
            int id = getJSONInt(body, json, idx, "id");
            int type = getJSONInt(body, json, idx, "type");
            int name = getJSONValue(body, json, idx, "name");
            if (id < 0 || name < 0 ||
                json[name].type != JSMN_STRING)
              continue;
            ret[i].shades = realloc(ret[i].shades,
                                    sizeof(struct shade) * ++ret[i].numShades);
            struct shade *shade = ret[i].shades + ret[i].numShades - 1;
            shade->name = malloc(json[name].end - json[name].start + 1);
            base64Decode(body + json[name].start, shade->name,
                         json[name].end - json[name].start);
            shade->id = id;
            shade->type = type;
            shade->position = -1;
            shade->scenemember = -1;
          }
        }
        free(json); json = NULL;
        free(body); body = NULL;

        // The desired position might need to be retrieved separately.
        sprintf(path, "/scenemembers?sceneId=%d", ret[i].id);
        if (request("GET", URL, path, 1, NULL, &body) == 200 &&
            body != NULL) {
          json = parseJSON(body);
          int sceneMemberData = getJSONValue(body, json, 0, "sceneMemberData");
          if (sceneMemberData >= 0 &&
              json[sceneMemberData].type == JSMN_ARRAY &&
              json[sceneMemberData].size == ret[i].numShades) {
            for (int j = 0, idx = json[sceneMemberData].first_child; idx != -1;
                 j++, idx = json[idx].next) {
              int id = getJSONInt(body, json, idx, "id");
              int shadeId = getJSONInt(body, json, idx, "shadeId");
              int position = getJSONInt(body, json, idx, "positions.position1");
              if (id < 0 || shadeId < 0)
                continue;
              if (position < 0) {
                char *bodySceneMember;
                sprintf(path, "/scenemembers/%d?refresh=true", id);
                if (request("GET", URL, path, 1, NULL, &bodySceneMember)==200 &&
                    bodySceneMember != NULL) {
                  jsmntok_t *jsonSceneMember = parseJSON(bodySceneMember);
                  position = getJSONInt(bodySceneMember, jsonSceneMember, 0,
                                        "sceneMember.positions.position1");
                  free(jsonSceneMember);
                }
                free(bodySceneMember);
              }
              int k = j;
              if (ret[i].shades[j].id != shadeId) {
                k = ret[i].numShades;
                while (k-- > 0 && ret[i].shades[k].id == shadeId) { }
              }
              if (k >= 0) {
                ret[i].shades[k].scenemember = id;
                ret[i].shades[k].position = position;
              }
            }
          }
        }
        free(json); json = NULL;
        free(body); body = NULL;
      }
      free(body); body = NULL;
    }

    // Sort shades by name. For identical names, sort by opacity.
    int cmpShadeNames(const void *a, const void *b) {
      int ret = strcmp(((struct shade *)a)->name, ((struct shade *)b)->name);
      if (ret) return ret;
      return ((struct shade *)a)->type - ((struct shade *)b)->type;
    }
    // Sort scenes in order of brightness.
    int weight(struct scene *scene) {
      int ret = 0;
      qsort(scene->shades, scene->numShades, sizeof(struct shade),
            cmpShadeNames);
      for (int i = scene->numShades; i-- > 0; ) {
        int position = scene->shades[i].position;
        if (position < 0) continue;
        position = 100-((100*position + (1 << 15) - 1) >> 16);
        // Dark shades contribute more heavily to darkening the room.
        ret += position * (scene->shades[i].type == 1 ? 1 : 3);
        // If shades have identical names, then they must be "stacked".
        // Subtract the darker shade's position from the lighter one.
        if (i && !strcmp(scene->shades[i].name, scene->shades[i-1].name) &&
            scene->shades[i].position >= 0) {
          position = (100-((100*scene->shades[--i].position +
                            (1 << 15) - 1) >> 16)) - position;
          if (position < 0) continue;
          ret += position;
        }
      }
      return ret;
    }
    int cmpScenes(const void *a, const void *b) {
      return weight((struct scene *)b) - weight((struct scene *)a);
    }
    qsort(ret, sceneCount, sizeof(struct scene), cmpScenes);

    // Copy shade information into the same malloced block, in order for the
    // caller to easily deallocate resources without having to know about the
    // organization of the entire data structure.
    size_t allocated = sceneCount * sizeof(struct scene);
    for (int i = sceneCount; i-- > 0; ) {
      if (!ret[i].numShades)
        continue;
      size_t offset = allocated;
      ret = realloc(ret, allocated += sizeof(struct shade) * ret[i].numShades);
      memcpy((char *)ret + offset, ret[i].shades,
             sizeof(struct shade) * ret[i].numShades);
      free(ret[i].shades);
      ret[i].shades = (struct shade *)offset;
    }
    // Do the same for the names of the shades.
    for (int i = sceneCount; i-- > 0; ) {
      for (int j = ret[i].numShades; j-- > 0; ) {
        size_t offset = allocated;
        char *name = FROMBASEREL(ret, ret[i].shades)[j].name;
        ret = realloc(ret, allocated += strlen(name) + 1);
        strcpy((char *)ret + offset, name);
        free(name);
        FROMBASEREL(ret, ret[i].shades)[j].name = (char *)offset;
      }
    }
    // Also copy the names of the scenes.
    for (int i = sceneCount; i-- > 0; ) {
      size_t offset = allocated;
      ret = realloc(ret, allocated += strlen(ret[i].name) + 1);
      strcpy((char *)ret + offset, ret[i].name);
      free(ret[i].name);
      ret[i].name = (char *)offset;
    }
    // Fix up all the string pointers, now that we no longer need to realloc()
    // and potentially move the memory block.
    for (int i = sceneCount; i-- > 0; ) {
      ret[i].name = FROMBASEREL(ret, ret[i].name);
      if (ret[i].numShades) {
        ret[i].shades = FROMBASEREL(ret, ret[i].shades);
        for (int j = ret[i].numShades; j-- > 0; ) {
          ret[i].shades[j].name = FROMBASEREL(ret, ret[i].shades[j].name);
        }
      }
    }

    if (numScenes) {
      *numScenes = sceneCount;
    }
    return ret;
  }
  return NULL;
}


// After editing the cached files to correctly reflect the scene descriptions,
// it is sometimes desirable to push this information to the controller. This
// function can do that, but it is normally unused as updating the scene
// configuration also updates physical shade position. That's usually not very
// desirable.
static void pushSceneData() __attribute__((unused));
static void pushSceneData(struct scene *scenes, int numScenes) {
  for (int i = numScenes; i-- > 0; ) {
    for (int j = scenes[i].numShades; j-- > 0; ) {
//    if (38834 != scenes[i].shades[j].scenemember) continue;
      char bufBody[256];
      char *header = NULL, *body;
      sprintf(body = bufBody,
              "{\"sceneMember\":{\"positions\":{\"posKind1\":1,"
              "\"position1\":%d},\"id\":%d,\"sceneId\":%d,\"shadeId\":%d}}",
              scenes[i].shades[j].position, scenes[i].shades[j].scenemember,
              scenes[i].id, scenes[i].shades[j].id);
      debug("POST /api/scenemembers/ HTTP/1.1\n%s\n\n%s\n\n", header ? header : "", body);
      int rc = request("POST", URL, "/scenemembers/", 0, &header, &body);
      debug("%d\n%s%s\n", rc, header, body);
    }
  }
}


// Tries to guess the active scene from the current position of the
// blinds. There is no proper API for doing this, and by definition
// this is not an exact procedure, as individual blinds might have been
// moved. Furthermore, it is a very expensive operation, as it takes
// a long time to query the blinds about their current position. The
// code therefore goes out of its way to minimize the number of calls
// to getShadePosition().
static struct scene *getCurrentScene(const struct scene *scenes, int numScenes){
  const struct scene *ret = NULL;

  // Maintain a list of possible candidates for the current scene.
  // As with a lot of the code in this project, we don't bother with
  // complicated data structures. We typically deal with extremely
  // small dataset. So, there really is no perceptible difference
  // between code that runs in O(n^2), O(n*log(n)), O(n), or for that
  // matter even O(1). After all, if n == 1, all of the above are
  // identical. Instead, we opt for simplicity of code.
  // Besides, even for larger values of n, execution time is dwarfed
  // by response time from the controller, which is orders of magnitude slower.
  const struct scene *candidates[numScenes];
  for (int i = numScenes; i-- > 0; ) {
    candidates[i] = scenes + i;
  }

  struct ids {
    int id, weight, numPos, *positions, type;
    const char *name;
  } *shadeIds = NULL;
  int numShades;

  // Keep iterating until we have narrowed things down to a single
  // scene, or until we are no longer making any progress.
  for (int lastNumScenes = numScenes;;) {
    debug("Number of candidate scenes: %d\n", numScenes);
    for (int i = numScenes; i-- > 0; ) {
      debug("%s%s%s", i == numScenes-1 ? "   " : "",
            candidates[i]->name, i ? ", " : "\n");
    }

    // Find all the shades that are affected by the current list of
    // possible scenes.
    numShades = 0;
    for (int i = numScenes; i-- > 0; ) {
      for (int j = candidates[i]->numShades; j-- > 0; ) {
        int k = numShades;
        while (k-- > 0 && shadeIds[k].id != candidates[i]->shades[j].id) { }
        if (k < 0) {
          shadeIds = realloc(shadeIds, ++numShades * sizeof(shadeIds[0]));
          shadeIds[numShades-1].id = candidates[i]->shades[j].id;
          shadeIds[numShades-1].name = candidates[i]->shades[j].name;
          shadeIds[numShades-1].type = candidates[i]->shades[j].type;
        }
      }
    }
    if (!numShades)
      goto err;

    // Determine how much additional information is gained by querying a
    // particular shade for it's current position.
    for (int i = numShades; i-- > 0; ) {
      // Find all the different positions that a particular shade can be in
      // for each of the different scenes.
      shadeIds[i].numPos = 0;
      shadeIds[i].positions = NULL;
      for (int j = numScenes; j-- > 0; ) {
        for (int k = candidates[j]->numShades; k-- > 0; ) {
          if (candidates[j]->shades[k].id == shadeIds[i].id) {
            shadeIds[i].positions = realloc(shadeIds[i].positions,
                                            ++shadeIds[i].numPos * sizeof(int));
            shadeIds[i].positions[shadeIds[i].numPos-1] =
              candidates[j]->shades[k].position;
            break;
          }
        }
      }
      // The most informative shade position is the one that splits the
      // decision tree into the most branches; preferably, into larger
      // rather than smaller branches. So, let's inspect the set of possible
      // positions and assign a weight to each set.
      int cmp(const void *a, const void *b) { return *(int *)b - *(int *)a; }
      qsort(shadeIds[i].positions, shadeIds[i].numPos, sizeof(int), cmp);
      shadeIds[i].weight = 1;
      debug("%s (%s):", shadeIds[i].name,
            shadeIds[i].type == 1 ? "transparent" : "black out");
      for (int j = shadeIds[i].numPos, k = -1, l = 0; j-- > 0; ) {
        debug(" %d", shadeIds[i].positions[j]);
        if (k == shadeIds[i].positions[j]) ++l;
        else {  shadeIds[i].weight *= l + 1; l = 1;
                k = shadeIds[i].positions[j]; }
        if (!j) shadeIds[i].weight *= l + 1;
      }
      debug("\n");
    }

    // Find the most favorable shade position that we should query.
    int cmp(const void *a, const void *b) {
      return ((struct ids *)a)->weight - ((struct ids *)b)->weight; }
    qsort(shadeIds, numShades, sizeof(struct ids), cmp);

    // For shades with identical weights, shuffle their order. This reduces
    // the reliance on a single shade to accurately report its position.
    for (int i = numShades, lastWeight = -1, start = numShades-1; i-- >= 0; ) {
      if (i < 0 || lastWeight != shadeIds[i].weight) {
        for (int j = start; j > i + 1; --j) {
          struct ids tmp = shadeIds[j];
          int idx = i + 1 + rand() % (start - i - 1);
          shadeIds[j] = shadeIds[idx];
          shadeIds[idx] = tmp;
        }
        if (i < 0) break;
        lastWeight = shadeIds[start = i].weight;
      }
    }

    // Retrieve the shade position. This doesn't always work 100% reliably,
    // as there could be communication issues with the shades. If so, try the
    // next shade.
    for (int i = numShades; i-- > 0; ) {
      // Hopefully, we will now receive a correct and up-to-date reading of
      // the current shade position.
      int position = getShadePosition(shadeIds[i].id);
      if (position < 0 || shadeIds[i].numPos <= 0) {
        continue;
      }
      // Shades occasionally get moved a small amount. Find the
      // closest position to what is part of a known scene.
      if (position < shadeIds[i].positions[shadeIds[i].numPos-1]) {
        position = shadeIds[i].positions[shadeIds[i].numPos-1];
      } else if (position > shadeIds[i].positions[0]) {
        position = shadeIds[i].positions[0];
      } else {
        int j = shadeIds[i].numPos-1; while (j-- > 0) {
          if (position <= shadeIds[i].positions[j] &&
              position >= shadeIds[i].positions[j+1]) {
            if (shadeIds[i].positions[j] - position  >
                position - shadeIds[i].positions[j+1]) {
              ++j;
            }
            break;
          }
        }
        position = shadeIds[i].positions[j];
      }

      // Compute the normalized position as we would see it in a
      // scene description.
      debug("Position normalized to %d\n", position);

      // Iterate over scenes and remove those, that don't match
      // the shade position.
      for (int j = numScenes; j-- > 0; ) {
        for (int k = candidates[j]->numShades; k-- > 0; ) {
          if (candidates[j]->shades[k].id == shadeIds[i].id) {
            if (candidates[j]->shades[k].position == position) {
              // This is a good candidate that still matches our
              // expectations.
              goto good;
            }
            break;
          }
        }
        // This scene doesn't match the observed shade position.
        // Remove it from the list of candidates.
        memmove(candidates + j, candidates + j + 1,
                (numScenes - j - 1) * sizeof(candidates[0]));
        --numScenes;
      good:;
      }
      break;
    }

    // We found a single scene description that matches the observed
    // shade positions.
    if (numScenes == 1) {
      ret = candidates[0];
      debug("Current configuration is %s\n", ret->name);
      break;
    } else if (numScenes == lastNumScenes) {
      // We are not making any progress. Give up.
      debug("Cannot determine current shade configuration\n");
      break;
    } else {
      lastNumScenes = numScenes;
    }

    for (int i = numShades; i-- > 0; ) {
      free(shadeIds[i].positions);
      shadeIds[i].positions = NULL;
    }
  }

err:
  for (int i = numShades; i-- > 0; ) {
    free(shadeIds[i].positions);
  }
  free(shadeIds);

  return (struct scene *)ret;
}


static int getNextEventTimeout(struct scene **activeScene, int numScenes) {
  struct scene *active = NULL;
  int previousEvent = -1, upcomingEvent = -1;
  char *body = NULL;
  jsmntok_t *json = NULL;

  // Check whether we are even following a schedule.
  if (request("GET", URL, "/userdata", 0, NULL, &body) != 200 || !body)goto err;
  json = parseJSON(body);
  if (getJSONBool(body, json, 0, "userData.enableScheduledEvents")!= 1)goto err;
  free(json); json = NULL;
  free(body); body = NULL;

  // Retrieve the current time, as maintained by the controller.
  if (request("GET", URL, "/times", 0, NULL, &body) != 200 || !body) goto err;
  json = parseJSON(body);
  int currentOffset = getJSONInt(body, json, 0, "times.currentOffset");
  int64_t currentUTC = getJSONUTC(body, json, 0, "times.currentUTC");
  int sunrise = getJSONInt(body, json, 0, "times.localSunriseTimeInMinutes");
  int sunset = getJSONInt(body, json, 0, "times.localSunsetTimeInMinutes");
  if (currentUTC < 0 || sunrise < 0 || sunset < 0) goto err;
  int64_t currentTime = currentUTC + currentOffset;
  int dayOfWeek = (currentTime / 86400 + 3) % 7; // Mon/0, Tue/1 .. Sun/6
  free(json); json = NULL;
  free(body); body = NULL;

  // Retrieve full list of scheduled events.
  if (request("GET", URL, "/scheduledevents",0,NULL,&body)!=200||!body)goto err;
  json = parseJSON(body);
  int events = getJSONValue(body, json, 0, "scheduledEventData");
  if (events < 0 || json[events].type != JSMN_ARRAY) goto err;

  // Parse all scheduled events and determine when they occur.
  for (int i = json[events].first_child; i>=0; i = json[i].next) {
    static const char *days[] = { "dayMonday", "dayTuesday", "dayWednesday",
                                  "dayThursday", "dayFriday", "daySaturday",
                                  "daySunday" };
    if (getJSONBool(body, json, i, "enabled") != 1) continue;
    int hour = getJSONInt(body, json, i, "hour");
    int minute = getJSONInt(body, json, i, "minute");
    int nextEvent =  (hour*60 + minute)*60 - (currentTime % 86400);
    switch (getJSONInt(body, json, i, "eventType")) {
    case 1: // Offset from sunrise
      nextEvent += sunrise*60;
      break;
    case 2: // Offset from sunset
      nextEvent += sunset*60;
      break;
    default: // Time of day
      break;
    }
    int day = dayOfWeek;

    // Determine the most recent scheduled event that happened in the past, and
    // return the associated scene information to the caller.
    // Look back up to a full week and a day, as some events might not be
    // scheduled every day of the week.
    for (int weekDays = 7; weekDays-- >= 0; ) {
      // Check if the event was enabled for this particular day of the week.
      if (nextEvent <= 0 && getJSONBool(body, json, i, days[day]) == 1) {
        // Update our idea of the most recent event.
        if (previousEvent < 0 || previousEvent > -nextEvent) {
          // Verify the scene actually matches one of the scenes for this room.
          int id = getJSONInt(body, json, i, "sceneId");
          int j = numScenes; while (j-- > 0 && (*activeScene)[j].id != id) { }
          if (j != -1) {
            previousEvent = -nextEvent;
            active = &(*activeScene)[j];
          }
        }
        break;
      }
      day = (day + 6) % 7;
      nextEvent -= 86400;
    }

    // Determine the next upcoming scheduled event in the future, and use the
    // information to set the next timeout value.
    // Look forward up to a full week and two days, as some events might not be
    // scheduled every day of the week.
    for (int weekDays = 8; weekDays-- >= 0; ) {
      // Check if the event is going to be enabled for this particular day.
      if (nextEvent >= 0 && getJSONBool(body, json, i, days[day]) == 1) {
        // Update our idea of the nearest upcoming event.
        if (upcomingEvent < 0 || nextEvent < upcomingEvent) {
          // Verify the scene actually matches one of the scenes for this room.
          int id = getJSONInt(body, json, i, "sceneId");
          int j = numScenes; while (j-- > 0 && (*activeScene)[j].id != id) { }
          if (j != -1) {
            upcomingEvent = nextEvent;
          }
        }
        break;
      }
      day = (day + 1) % 7;
      nextEvent += 86400;
    }
  }
 err:
  free(json);
  free(body);

  // Add a small fudge factor after the event.
  if (upcomingEvent >= 0) {
    upcomingEvent += 4;
  }

  // Every DEFAULT_TIMEOUT we double-check that things haven't been
  // changed manually.
  if (upcomingEvent < 0 || upcomingEvent > DEFAULT_TIMEOUT) {
    upcomingEvent = DEFAULT_TIMEOUT;
  }

  // If the caller requested this information, return the currently active scene
  *activeScene = active;

  return upcomingEvent;
}


#ifdef WIRING
static void init(void) {
  wiringPiSetup();
  pinMode(UP, INPUT);
  pinMode(DOWN, INPUT);
  pullUpDnControl(UP, PUD_UP);
  pullUpDnControl(DOWN, PUD_UP);
  return;
}


static int getState(void) {
  int up   = digitalRead(UP);
  int down = digitalRead(DOWN);
  return ((up << 1) | down) ^ 3;
}
#endif


int main(int argc, char *argv[]) {
//size_t len;
//char *mem = getMemoryDump(&len);
//write(1, mem, len);
//free(mem);
//return 0;

  int roomId = getRoomId(ROOM);
  int numScenes;
  struct scene *scenes = getScenes(roomId, &numScenes);

//pushSceneData(scenes, numScenes);

  _Atomic int currentScene = 0;

  // The shade configuration can be changed because of a scheduled
  // event or because of manual operation. Since checking the current
  // current configuration is a potentially expensive operation, we do
  // so in a separate thread.
  void sigalrm(int _) { debug("Scene was changed manually; rescanning now\n"); }
  void *monitorConfigChanges(void *arg) {
    sigset_t mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGALRM);
    sigprocmask(SIG_BLOCK, &mask, &mask);
    sigdelset(&mask, SIGALRM);
    sigaction(SIGALRM, &(struct sigaction){ .sa_handler = sigalrm }, NULL);

    // "currentScene" always maintains the most accurate idea of what we
    // believe the currently active scene looks like. But we maintain
    // "lastScheduledScene" (the most recent scene activated by a scheduled
    // event) and "lastProbedScene" (the scene possibly activated by manual
    // changes with the remote control) as additional state variables that get
    // copie to "currentScene", when appropriate.
    struct scene *lastScheduledScene = NULL;
    struct scene *lastProbedScene = NULL, *tentativeScene = NULL;
    int confirmationCounter = 0, recentChanges = 0;
    for (;;) {
      struct scene *activeScene = scenes;
      int timeOut = getNextEventTimeout(&activeScene, numScenes);
      if (activeScene != lastScheduledScene) {
        lastScheduledScene = activeScene;
        if (lastScheduledScene) {
          currentScene = lastScheduledScene - scenes;
          debug("Currently scheduled scene: %s\n", activeScene->name);
        }
        recentChanges = 3;
      }

      // Regularly check whether the shade configuration has been changed
      // manually.
      activeScene = getCurrentScene(scenes, numScenes);
      if (activeScene == lastProbedScene) {
        tentativeScene = NULL;
        confirmationCounter = 0;
      } else if (activeScene != tentativeScene) {
        if (activeScene) {
          debug("Scene tentatively changed to %s\n",
                activeScene->name);
        }
        tentativeScene = activeScene;
        confirmationCounter = 3;
      } else if (--confirmationCounter <= 0) {
        if (activeScene) {
          printf("The active PowerView scene has been changed to %s\n",
                 activeScene->name);
        }
        lastProbedScene = activeScene;
        tentativeScene = NULL;
        confirmationCounter = 0;
      }
      // Aggressively update the current configuration, even if we haven't been
      // able to confirm yet. If it was just a random intermittent wrong result,
      // it'll fix itself and nobody will notice. But if it was a real change,
      // it is advantageous to reflect the change immediately.
      if (activeScene && currentScene != activeScene - scenes) {
        recentChanges = 3;
        currentScene = activeScene - scenes;
      }

      // Whenever there has been a configuration change, check for
      // additional changes more frequently.
      if ((recentChanges || confirmationCounter) &&
          (timeOut < 0 || timeOut > SHORT_TIMEOUT)) {
        timeOut = SHORT_TIMEOUT;
      }
      if (confirmationCounter) --confirmationCounter;
      if (recentChanges)       --recentChanges;

      // Wait for timeout to expire.
      debug("Sleeping %d seconds\n", timeOut);
      ppoll(NULL, 0, &(struct timespec){ .tv_sec = timeOut }, &mask);
    }
    return 0;
  }

#ifdef WIRING
  pthread_t configurationWatcher;
  pthread_create(&configurationWatcher, NULL, monitorConfigChanges, NULL);

  // The good news is that GPIO pins are memory mapped and any application
  // running as root can access them very fast without even having to make
  // a system call. The bad news is that for our target platform, there is
  // no way to generate interrupts when GPIO pins change. So, we must poll
  // them very regularly.
  init();
  time_t lastRequest = 0;
  for (int state = getState(), last = 0, deep = 0;;) {
    int s = getState();
    if (s != state) {
      last = millis();
      state = s;
    } else if (last) {
      if (millis() - last > DEBOUNCE) {
        last = 0;
        deep = 1*1000/SLEEP;
        if (state) {
          if (state & 2) /* UP */ {
            if (currentScene) {
              currentScene--;
            } else {
              // If we reached the first scene and the user keeps pressing the
              // button, ignore these button presses. On the other hand, if
              // some time has passed and the user still presses the button,
              // maybe this is an indication that our idea of the "currently
              // active scene" is incorrect.
            maybeIgnore:;
              time_t tm = time(NULL);
              if (!lastRequest || (unsigned)(tm-lastRequest) > REPEAT_TIMEOUT) {
                continue;
              } else {
                lastRequest = tm;
              }
            }
          } else /* DOWN */ {
            if (currentScene < numScenes-1) {
              currentScene++;
            } else {
              goto maybeIgnore;
            }
          }
          printf("Button pushed and PowerView scene adjusted to %s\n",
                 scenes[currentScene].name);
          char path[80];
          sprintf(path, "/scenes?sceneid=%d", scenes[currentScene].id);
          debug("%s\n", path);
          char *body = 0;
          request("GET", URL, path, 0, NULL, &body);
          lastRequest = time(NULL);
          debug("%s\n", body);
          free(body);
        }
      }
    } else {
      if (deep) {
        --deep;
        usleep(SLEEP*1000);
      } else {
        usleep(DEEP_SLEEP*1000);
      }
    }
  }
  return 0;
#else
  monitorConfigChanges(NULL);
#endif

  free(scenes);
  _exit(0);
}
