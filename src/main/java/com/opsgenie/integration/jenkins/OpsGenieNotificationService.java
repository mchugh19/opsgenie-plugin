package com.opsgenie.integration.jenkins;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import hudson.ProxyConfiguration;
import hudson.model.*;
import hudson.scm.ChangeLogSet;
import hudson.tasks.test.AbstractTestResultAction;
import hudson.tasks.test.TestResult;
import jenkins.model.Jenkins;
import jenkins.model.JenkinsLocationConfiguration;
import net.sf.json.JSONObject;

import org.apache.commons.lang.StringUtils;
import org.apache.http.HttpHost;
import org.apache.http.HttpResponse;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.client.HttpClient;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.util.EntityUtils;
import org.slf4j.LoggerFactory;

import java.io.PrintStream;
import java.net.URI;
import java.util.*;
import java.util.regex.Pattern;

/**
 * @author Omer Ozkan
 * @author kaganyildiz
 * @version 09/07/17
 */

public class OpsGenieNotificationService {
    private final static String INTEGRATION_PATH = "/v2/alerts";

    private final org.slf4j.Logger logger = LoggerFactory.getLogger(OpsGenieNotificationService.class);

    private final Run<?, ?> build;
    private final Job<?, ?> project;
    private final AlertProperties alertProperties;
    private final PrintStream consoleOutputLogger;
    private final Map<String, Object> requestPayload;
    private final ObjectMapper mapper;
    private final OpsGenieNotificationRequest request;

    public OpsGenieNotificationService(final OpsGenieNotificationRequest request) {
        build = request.getBuild();
        project = build.getParent();

        this.request = request;
        mapper = new ObjectMapper();
        mapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        requestPayload = new HashMap<>();

        alertProperties = request.getAlertProperties();
        consoleOutputLogger = request.getListener().getLogger();
    }

    private boolean checkResponse(final String res) {
        try {
            final ResponseFromOpsGenie response = mapper.readValue(res, ResponseFromOpsGenie.class);
            if (StringUtils.isEmpty(response.error)) {
                consoleOutputLogger.println("Sending job data to OpsGenie is done");
                return true;
            } else {
                consoleOutputLogger.println("Response status is failed");
                logger.error("Response status is failed");
                return false;
            }
        } catch (final Exception e) {
            e.printStackTrace(consoleOutputLogger);
            logger.error("Exception while checking response" + e.getMessage());
        }
        return !res.isEmpty();
    }

    private String sendWebhookToOpsGenie(final String data) {
        try {
            final String apiUrl = this.request.getApiUrl();
            final String apiKey = this.request.getApiKey();

            final URI inputURI = new URI(apiUrl);
            String scheme = "https";
            String host = apiUrl;
            if (inputURI.isAbsolute()) {
                scheme = inputURI.getScheme();
                host = inputURI.getHost();
            }

            final URI uri = new URIBuilder().setScheme(scheme).setHost(host).setPath(INTEGRATION_PATH)
                    .addParameter("apiKey", apiKey).build();

            HttpClient client;

            final HttpPost post = new HttpPost(uri);
            final JSONObject JSO = JSONObject.fromObject(data);
            final StringEntity params = new StringEntity(JSO.toString());
            post.setEntity(params);
            post.addHeader("Content-Type", "application/json");

            if (Jenkins.getInstance() != null && Jenkins.getInstance().proxy != null) {
                // A proxy is configured, so we will use it for this request as well.
                final ProxyConfiguration proxy = Jenkins.getInstance().proxy;

                // Check if the host of opsgenie is excluded from the proxy.
                Boolean isHostExcludedFromProxy = false;
                for (final Pattern pattern : proxy.getNoProxyHostPatterns()) {
                    if (pattern.matcher(host).matches()) {
                        isHostExcludedFromProxy = true;
                    }
                }

                if (!isHostExcludedFromProxy) {
                    // Host is not excluded from proxy.
                    if (proxy.getUserName() != null && proxy.getPassword() != null) {
                        // Authentication for proxy is configured.
                        final CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
                        credentialsProvider.setCredentials(new AuthScope(proxy.name, proxy.port),
                                new UsernamePasswordCredentials(proxy.getUserName(), proxy.getPassword()));
                        client = HttpClientBuilder.create().setDefaultCredentialsProvider(credentialsProvider).build();
                    } else {
                        client = HttpClientBuilder.create().build();
                    }

                    final HttpHost proxyHost = new HttpHost(proxy.name, proxy.port);
                    final RequestConfig config = RequestConfig.custom().setProxy(proxyHost).build();

                    post.setConfig(config);
                } else {
                    // Proxy is configured but opsgenie should not use the proxy.
                    client = HttpClientBuilder.create().build();
                }
            } else {
                // No proxy is configured.
                client = HttpClientBuilder.create().build();
            }

            consoleOutputLogger.println("Sending job data to OpsGenie...");
            final HttpResponse response = client.execute(post);

            return EntityUtils.toString(response.getEntity());
        } catch (final Exception e) {
            e.printStackTrace(consoleOutputLogger);
            logger.error("Exception while sending webhook: " + e.getMessage());
        }
        return "";
    }

    protected boolean sendPreBuildPayload() {

        populateRequestPayloadWithMandatoryFields();

        requestPayload.put("isPreBuild", "true");

        if (alertProperties.getBuildStartPriority() != null) {
            requestPayload.put("priority", alertProperties.getBuildStartPriority().getValue());
        }

        JSONObject payload = new JSONObject();
        try {
            payload = JSONObject.fromObject(requestPayload);
        } catch (final Exception e) {
            e.printStackTrace(consoleOutputLogger);
            logger.error("Exception while serializing pre request:" + e.getMessage());
        }
        final String response = sendWebhookToOpsGenie(payload.toString());

        return checkResponse(response);
    }

    private String formatCommitList(final ChangeLogSet<? extends ChangeLogSet.Entry> changeLogSet) {
        final StringBuilder commitListBuilder = new StringBuilder();
        if (changeLogSet.isEmptySet()) {
            commitListBuilder.append("No changes.\n\n");
        }

        for (final ChangeLogSet.Entry entry : changeLogSet) {
            commitListBuilder.append(entry.getMsg()).append(" - <strong>").append(entry.getAuthor().getDisplayName())
                    .append("</strong><br>\n");
        }
        return commitListBuilder.toString();
    }

    private String formatFailedTests(final List<? extends TestResult> failedTests) {
        final StringBuilder testResultBuilder = new StringBuilder();
        for (final TestResult failedTest : failedTests) {
            testResultBuilder.append(String.format("<strong>%s</strong>%n", failedTest.getFullName()));

            if (StringUtils.isNotBlank(failedTest.getErrorDetails())) {
                testResultBuilder.append(failedTest.getErrorDetails());
            }

            testResultBuilder.append("\n\n");
        }
        return testResultBuilder.toString();
    }

    private String formatBuildVariables() {
        final StringBuilder buildVariablesBuilder = new StringBuilder();
        if (build instanceof AbstractBuild) {
            final Map<String, String> buildVariables = ((AbstractBuild<?, ?>) build).getBuildVariables();
            for (final Map.Entry<String, String> entry : buildVariables.entrySet()) {
                buildVariablesBuilder.append(entry.getKey()).append(" -> ").append(entry.getValue()).append("\n");
            }
        }
        return buildVariablesBuilder.toString();
    }

    public boolean sendAfterBuildData() {
        Map details = new HashMap();
        populateRequestPayloadWithMandatoryFields();

        if (build instanceof AbstractBuild) {
            if (build.getResult() == Result.FAILURE || build.getResult() == Result.UNSTABLE) {
                final Set<User> culprits = ((AbstractBuild<?, ?>) build).getCulprits();
                if (!culprits.isEmpty()) {
                    details.put("culprits", formatCulprits(culprits));
                }
            }
        }

        final StringBuilder descriptionBuilder = new StringBuilder();
        final AbstractTestResultAction<?> testResult = build.getAction(AbstractTestResultAction.class);
        if (testResult != null) {
            final String passedTestCount = Integer
                    .toString(testResult.getTotalCount() - testResult.getFailCount() - testResult.getSkipCount());
            details.put("passedTestCount", passedTestCount);
            final String failedTestCount = Integer.toString(testResult.getFailCount());
            details.put("failedTestCount", failedTestCount);
            final String skippedTestCount = Integer.toString(testResult.getSkipCount());
            details.put("skippedTestCount", skippedTestCount);

            if (build.getResult() == Result.UNSTABLE || build.getResult() == Result.FAILURE) {
                descriptionBuilder.append(formatFailedTests(testResult.getFailedTests()));
                details.put("failedTests", descriptionBuilder);
            }
        }

        if (build instanceof AbstractBuild) {
            details.put("commitList", formatCommitList(((AbstractBuild<?, ?>) build).getChangeSet()));
        }
        final Run<?, ?> previousBuild = build.getPreviousBuild();
        if (previousBuild != null) {
            final String previousDisplayName = previousBuild.getDisplayName();
            details.put("previousDisplayName", previousDisplayName);
            final String previousTime = previousBuild.getTimestamp().getTime().toString();
            details.put("previousTime", previousTime);
            final Result previousResult = previousBuild.getResult();
            if (previousResult != null) {
                details.put("previousStatus", previousResult.toString());
            }
            final Job<?, ?> previousProject = previousBuild.getParent();
            if (previousProject != null) {
                final String previousProjectName = previousProject.getName();
                details.put("previousProjectName", previousProjectName);
            }
        }

        details.put("isPreBuild", "false");
        details.put("duration", build.getDurationString());
        details.put("params", formatBuildVariables());

        if (alertProperties.getPriority() != null) {
            requestPayload.put("priority", alertProperties.getPriority().getValue());
        }

        requestPayload.put("details", details);

        String payload = "";
        try {
            payload = this.mapper.writerWithDefaultPrettyPrinter().writeValueAsString(requestPayload);
        } catch (final Exception e) {
            e.printStackTrace(consoleOutputLogger);
            logger.error("Exception while serializing post request :" + e.getMessage());
        }

        final String response = sendWebhookToOpsGenie(payload);
        return checkResponse(response);
    }

    private String formatCulprits(final Set<User> culprits) {
        final StringBuilder culpritsBuilder = new StringBuilder();
        for (final User culprit : culprits) {
            culpritsBuilder.append(culprit.getFullName()).append(",");
        }
        return culpritsBuilder.toString();
    }

    private void populateRequestPayloadWithMandatoryFields() {

        String description = "";
        String displayName = build.getDisplayName();
        final String projectName = project.getName();
        description += "Job: " + projectName + "\n";
        description += "JobNumber: " + displayName + "\n";

        Result status = build.getResult();
        if (status == null) {
            // Build may still be ongoing
            status = Result.SUCCESS;
        }
        description += "Status: " + Objects.toString(status) + "\n";

        final String url = build.getUrl();
        final String jenkinsSite = new JenkinsLocationConfiguration().getUrl();
        final String fullJenkinsURL = jenkinsSite + url;
        requestPayload.put("source", fullJenkinsURL);

        List<String> tags = splitStringWithComma(alertProperties.getTags());
        tags.add("jenkins");
        tags.add(Objects.toString(status));
        requestPayload.put("tags", tags);

        // List<String> teams = splitStringWithComma(alertProperties.getTeams());
        // requestPayload.put("teams", teams);
        requestPayload.put("message", "Project: " + projectName + " Status: " + Objects.toString(status));
        requestPayload.put("description", description);
        requestPayload.put("alias", "Project: " + projectName + " Status: " + Objects.toString(status));
    }

    private List<String> splitStringWithComma(final String unparsed) {
        if (unparsed == null) {
            return Collections.emptyList();
        }

        final ArrayList<String> tokens = new ArrayList<>();

        for (final String token : unparsed.trim().split(",")) {
            tokens.add(token.trim());
        }

        return tokens;
    }

    @JsonIgnoreProperties(ignoreUnknown = true)
    public static class ResponseFromOpsGenie {

        @JsonProperty("error")
        private String error;

        public String getError() {
            return error;
        }

        public void setError(final String error) {
            this.error = error;
        }
    }
}
