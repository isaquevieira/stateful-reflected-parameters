package burp;

import java.net.URL;
import java.util.ArrayList;
import java.util.List;

class ReflectedEntry {
    final IHttpRequestResponseWithMarkers requestResponse;  // Request and response
    final URL url;                                          // Request URL
    final String method;                                    // Method used in the request
    final String tool;                                      // Tool name from which the request was sent
    List<String[]> parameters;                              // Parameter names with the values

    ReflectedEntry() {
        requestResponse = null;
        url = null;
        tool = null;
        method = null;
        parameters = new ArrayList<>();
    }

    ReflectedEntry(IHttpRequestResponseWithMarkers requestResponse, URL url, String method, List<String[]> parameters, String tool) {
        this.requestResponse = requestResponse;
        this.url = url;
        this.method = method;
        this.parameters = parameters;
        this.tool = tool;
    }
}
