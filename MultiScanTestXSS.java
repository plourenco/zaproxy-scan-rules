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

public class MultiScanTestXSS extends AbstractAppParamPlugin {

    private static Logger log = Logger.getLogger(MultiScanTestXSS.class);
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        boolean attackWorked = false;

        if (isStop()) {
            return;
        }

        List<HtmlContext> contexts = performAttack (msg, param,
                "' OR '1' = '1", null, 0);
        if (contexts == null) {
            return;
        }
        if (contexts.size() > 0) {
            // Yep, its vulnerable
            bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_LOW, null, param, contexts.get(0).getTarget(),
                    "", contexts.get(0).getTarget(), contexts.get(0).getMsg());
            attackWorked = true;
            for(HtmlContext hc : contexts) {
                System.out.println(hc.getTarget()
                        + " " + hc.getTagAttribute() + " " + hc.getSurroundingQuote());
                System.out.println(hc.getMsg().getRequestBody().getBytes());
            }
        }
    }

    @Override
    public int getId() {
        return 0;
    }

    @Override
    public String getName() {
        return "MultiScanTestXSS";
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

    private List<HtmlContext> performAttack (HttpMessage msg, String param, String attack,
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
            return hca.getHtmlContexts(attack, targetContext, ignoreFlags);
        }
        return hca.getHtmlContexts(attack);
    }
}