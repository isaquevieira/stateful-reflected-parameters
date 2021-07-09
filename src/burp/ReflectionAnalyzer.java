package burp;

import org.json.JSONArray;
import org.json.JSONObject;

import java.io.PrintWriter;
import java.net.URL;
import java.util.*;
import java.util.stream.Collectors;

import static java.util.Collections.*;

class HistoryEntry {
    IHttpRequestResponse response;
    JSONObject json;

    public HistoryEntry(IHttpRequestResponse response, JSONObject json) {
        this.response = response;
        this.json = json;
    }

    @Override
    public String toString() {
        return "HistoryEntry{" +
                "\njson=" + json +
                "\n}";
    }
}

class Param {
    HistoryEntry producer;
    String[] values;

    Param(HistoryEntry producer, String[] values) {
        this.producer = producer;
        this.values = values;
    }

    @Override
    public String toString() {
        return "Param{\n" +
                "producer=" + producer +
                ", \nvalues=" + Arrays.toString(values) +
                '}';
    }
}

public class ReflectionAnalyzer {
    private final IBurpExtenderCallbacks callbacks;
    private final PrintWriter stdout;
    private final IExtensionHelpers helpers;
    List<HistoryEntry> historicOfRequests = new ArrayList<>();

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
                return checkIfAValueExistsInJSONObject((JSONObject) jsonObject.get(key), value);
            } else {
                if (value.equals(jsonObject.get(key).toString())) {
                    return true;
                }
            }
        }
        return false;
    }

    public List<HistoryEntry> isContainedOnRequestHistory(String key) {
        List<HistoryEntry> result = new ArrayList<>();
        for (HistoryEntry out : historicOfRequests) {
            if (checkIfAValueExistsInJSONObject(out.json, key)) {
                result.add(out);
            }
        }
        return result;
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

                JSONObject resObj = new JSONObject(responseBody);
                historicOfRequests.add(new HistoryEntry(messageInfo, resObj));
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

        IRequestInfo iRequest = helpers.analyzeRequest(messageInfo.getRequest());
        IHttpRequestResponseWithMarkers messageInfoMarked = callbacks.applyMarkers(messageInfo, null, null);
        List<int[]> requestMarkers = new ArrayList<>();
        List<int[]> responseMarkers = new ArrayList<>();
        List<Param> parameters = new ArrayList<>();

        for (IParameter param : iRequest.getParameters()) {
            if (param.getValue().isBlank()) {
                continue;
            }

            List<HistoryEntry> producer = isContainedOnRequestHistory(param.getValue());

            if (producer.size() > 0) {
                requestMarkers.add(new int[] {param.getValueStart(),param.getValueEnd()});
                messageInfoMarked = callbacks.applyMarkers(messageInfo, requestMarkers, responseMarkers);
                String[] paramValues = new String[]{param.getName(), param.getValue(), param.getValue()/*String.join(",", reflectedValues)*/};

                producer.forEach(item->parameters.add(new Param(item, paramValues)));
            }
        }

        for (String param : getParamsFromURL(url)) {
            if (param.isBlank()) {
                continue;
            }

            List<HistoryEntry> producer = isContainedOnRequestHistory(param);

            if (producer.size() > 0) {
                String[] paramValues = new String[]{param, param, param};
                producer.forEach(item->parameters.add(new Param(item, paramValues)));
            }
        }

        if (parameters.size() < 1) {
            return null;
        }

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
