package org.zaproxy.zap.extension.ascanrules;

import org.apache.commons.httpclient.InvalidRedirectLocationException;
import org.apache.commons.httpclient.URIException;
import org.apache.log4j.Logger;
import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.core.scanner.Plugin;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.httputils.HtmlContext;
import org.zaproxy.zap.httputils.HtmlContextAnalyser;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

import java.net.UnknownHostException;
import java.util.List;

/**
 * SQL Injection test using the Selenium Web Driver Tool
 * 19 December 2016
 * @author pedroo21
 */
public class TestSQLInjectionV2 extends AbstractAppParamPlugin {

    private static Logger log = Logger.getLogger(TestSQLInjectionV2.class);
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");
    private JSONUtils config;

    /**
     * generic one-line comment. Various RDBMS Documentation suggests that this
     * syntax works with almost every single RDBMS considered here
     */
    private final String SQL_ONE_LINE_COMMENT = " -- ";

    /**
     * always true statement for comparison if no output is returned from AND in
     * boolean based SQL injection check Note that, if necessary, the code also
     * tries a variant with the one-line comment " -- " appended to the end.
     */
    private final String[] SQL_LOGIC_OR_TRUE = {
            " OR 1=1" + SQL_ONE_LINE_COMMENT,
            "' OR '1'='1'" + SQL_ONE_LINE_COMMENT,
            "\" OR \"1\"=\"1\"" + SQL_ONE_LINE_COMMENT,
            " OR 1=1",
            "' OR '1'='1",
            "\" OR \"1\"=\"1",
            "%", //attack for SQL LIKE statements
            "%' " + SQL_ONE_LINE_COMMENT, //attack for SQL LIKE statements
            "%\" " + SQL_ONE_LINE_COMMENT, //attack for SQL LIKE statements
    };

    @Override
    public void scan(HttpMessage msg, String param, String value) {

        config = new JSONUtils();
        config.readConfig();

        for(String sql : SQL_LOGIC_OR_TRUE) {

            if (isStop()) {
                return;
            }

            for(String test : config.getSQLSuccess()) {
                List<HtmlContext> contexts = performAttack(msg, param,
                        sql, test, null, 0);
                if (contexts == null) {
                    return;
                }
                if (contexts.size() > 0) {
                    // Yep, its vulnerable
                    bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, null, param, contexts.get(0).getTarget(),
                            "", contexts.get(0).getTarget(), contexts.get(0).getMsg());
                }
            }
        }
    }

    /**
     * NECESSARY METHODS FOR ZAP PLUGIN
     */
    @Override
    public int getId() {
        return 0;
    }

    @Override
    public String getName() {
        return "TestSQLInjectionV2";
    }

    @Override
    public String[] getDependency() {
        return null;
    }

    @Override
    public String getDescription() {
        if (vuln != null) {
            return vuln.getDescription();
        }
        return "Failed to load vulnerability description from file";
    }

    @Override
    public int getCategory() {
        return Category.INJECTION;
    }

    @Override
    public String getSolution() {
        if (vuln != null) {
            return vuln.getSolution();
        }
        return "Failed to load vulnerability solution from file";
    }

    @Override
    public String getReference() {
        if (vuln != null) {
            StringBuilder sb = new StringBuilder();
            for (String ref : vuln.getReferences()) {
                if (sb.length() > 0) {
                    sb.append('\n');
                }
                sb.append(ref);
            }
            return sb.toString();
        }
        return "Failed to load vulnerability reference from file";
    }

    @Override
    public void init() {

    }

    /**
     * Clone the request, send and receive and look evidences of attack
     * @param msg msg
     * @param param param
     * @param attack attack
     * @param lookup lookup
     * @param targetContext targetContext
     * @param ignoreFlags ignoreFlags
     * @return successContexts
     */
    private List<HtmlContext> performAttack (HttpMessage msg, String param, String attack,
                                             String lookup,
                                             HtmlContext targetContext, int ignoreFlags) {
        if (isStop()) {
            return null;
        }

        HttpMessage msg2 = msg.cloneRequest();
        setParameter(msg2, param, attack);
        try {
            sendAndReceive(msg2);
        } catch (URIException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to send HTTP message, cause: " + e.getMessage());
            }
            return null;
        } catch (InvalidRedirectLocationException |UnknownHostException e) {
            // Not an error, just means we probably attacked the redirect location
            return null;
        } catch (Exception e) {
            log.error(e.getMessage(), e);
        }

        if (isStop()) {
            return null;
        }

        HtmlContextAnalyser hca = new HtmlContextAnalyser(msg2);
        if (Plugin.AlertThreshold.HIGH.equals(this.getAlertThreshold())) {
            // High level, so check all results are in the expected context
            return hca.getHtmlContexts(lookup, targetContext, ignoreFlags);
        }
        return hca.getHtmlContexts(lookup);
    }
}