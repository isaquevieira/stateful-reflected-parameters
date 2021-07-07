package burp;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;

import static java.util.Collections.*;

public class ReflectionAnalyzer {
    private final IBurpExtenderCallbacks callbacks;
    private final PrintWriter stdout;
    private final IExtensionHelpers helpers;
    List<HistoryEntry> historicOfRequests = new ArrayList<>();

    private class HistoryEntry {
        IHttpRequestResponse response;
        JSONObject json;

        public HistoryEntry(IHttpRequestResponse response, JSONObject json) {
            this.response = response;
            this.json = json;
        }
    }

    public ReflectionAnalyzer(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
    }

    public static boolean checkIfAValueExistsInJSONObject(JSONObject jsonObject, String value) {
        for (String key : jsonObject.keySet()) {
            if (jsonObject.get(key) instanceof JSONArray) {
                JSONArray array = jsonObject.getJSONArray(key);
                for (Object child : array) {
                    if (checkIfAValueExistsInJSONObject((JSONObject) child, value)) {
                        return true;
                    }
                }
            } else if (jsonObject.get(key) instanceof JSONObject) {
                return checkIfAValueExistsInJSONObject(jsonObject.getJSONObject(key), value);
            } else {
                return value.equals(jsonObject.get(key).toString());
            }
        }
        return false;
    }

    public boolean isContainedOnRequestHistory(String key) {
        for (HistoryEntry out : historicOfRequests) {
            if (checkIfAValueExistsInJSONObject(out.json, key)) {
                return true;
            }
        }
        return false;
    }

    // ref: https://stackoverflow.com/a/24372548
    // ref: https://stackoverflow.com/a/30709527/13912378
    // Extract the values from a JSON object
    //TODO: remove
    // Nao foi removido ainda pq pode ser útil para referencia
    public static List<String> printJSONObject(JSONObject resobj) {
        List<String> values = new ArrayList<>();
        for (String key : resobj.keySet()) {
            if (resobj.get(key) instanceof JSONObject) {
                JSONObject child = new JSONObject(resobj.get(key).toString());
                values.addAll(printJSONObject(child));
            } else {
                values.add(resobj.get(key).toString());
            }
        }
        return values;
    }

    private boolean isFromAcceptedTool(int toolFlag) {
        return toolFlag == IBurpExtenderCallbacks.TOOL_PROXY || toolFlag == IBurpExtenderCallbacks.TOOL_REPEATER;
    }

    public void analyzeHttpResponse(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // Process only responses from Proxy or Repeater
        if (messageIsRequest || !isFromAcceptedTool(toolFlag))
            return;

        // Check if it is in scope
        if (!callbacks.isInScope(helpers.analyzeRequest(messageInfo).getUrl()))
            return;

        IResponseInfo iResponse = helpers.analyzeResponse(messageInfo.getResponse());

        // Verify if the request is JSON
        if (iResponse.getInferredMimeType().equals("JSON")) {
            stdout.println("Analyzing HttpResponse");
            try {
                String response = new String(messageInfo.getResponse());
                int bodyOffset = iResponse.getBodyOffset();
                String responseBody = response.substring(bodyOffset);

                stdout.println("responseBody: " + responseBody);
                JSONObject resobj = new JSONObject(responseBody);
                historicOfRequests.add(new HistoryEntry(messageInfo, resobj));

                stdout.println("Current JSONObject:");
                for (String out : printJSONObject(resobj)) {
                    stdout.println(out);
                }

                stdout.println("Current historicOfRequestsMap state:");
                for (HistoryEntry out : historicOfRequests) {
                    for (String mapOut : out.json.keySet()) {
                        stdout.println(mapOut + ":" + out.json.get(mapOut));
                    }
                }
            } catch (Exception e) {
                System.out.println("Error to parser JSON");
                e.printStackTrace();
            }
        }
    }

    // Look for refection in HttpRequests
    protected ReflectedEntry analyzeHttpRequest(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        // Process only requests from Proxy, or Repeater
        if (!messageIsRequest || !isFromAcceptedTool(toolFlag))
            return null;

        URL url = helpers.analyzeRequest(messageInfo).getUrl();
        if (!callbacks.isInScope(url))
            return null;

        stdout.println("Analyzing HttpRequest");

        IRequestInfo iRequest = helpers.analyzeRequest(messageInfo.getRequest());
        IHttpRequestResponseWithMarkers messageInfoMarked = callbacks.applyMarkers(messageInfo, null, null);
        List<int[]> requestMarkers = new ArrayList<>();
        List<int[]> responseMarkers = new ArrayList<>();
        List<String[]> parameters = new ArrayList<>();
        List<String> reflectedValues = new ArrayList<>();

        stdout.println("Listing params");
        for (IParameter param : iRequest.getParameters()) {
            stdout.println(param.getValue());
            if (param.getValue().isBlank()) {
                continue;
            }

            if (isContainedOnRequestHistory(param.getValue())) {
                stdout.println("Reflected Value found: " + param.getValue());
                reflectedValues.add(param.getValue());
                requestMarkers.add(new int[] {param.getValueStart(),param.getValueEnd()});
                messageInfoMarked = callbacks.applyMarkers(messageInfo, requestMarkers, responseMarkers);
                parameters.add(new String[]{param.getName(), param.getValue(), String.join(",", reflectedValues)});
            }
        }

        stdout.println(url);
        for (String param : getParamsFromURL(url)) {
            if (param.isBlank()) {
                continue;
            }
            stdout.println(String.format("path param: %s", param));

            if (isContainedOnRequestHistory(param)) {
                reflectedValues.add(param);
                parameters.add(new String[]{param, param, String.join(",", reflectedValues)});
            }
        }
//
//                // TODO: scan headers
//                List<String> headers = iRequest.getHeaders();
//                for (String header: headers) {
//                	stdout.println(header);
//                }
        if (parameters.size() < 1) {
            return null;
        }

        stdout.println("Reflected params");
        for (String[] param : parameters) {
            stdout.println(Arrays.toString(param));
        }
        stdout.println("----------------");

        return new ReflectedEntry(
                messageInfoMarked,
                helpers.analyzeRequest(messageInfo).getUrl(),
                helpers.analyzeRequest(messageInfo).getMethod(),
                parameters,
                callbacks.getToolName(toolFlag)
        );
    }

    private List<String> getParamsFromURL(URL url) {
        return Arrays.asList(url.getPath().split("/"));
    }
}
