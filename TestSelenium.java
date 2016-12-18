package org.zaproxy.zap.extension.ascanrules;

import java.net.UnknownHostException;
import java.util.List;
import java.util.concurrent.TimeUnit;

import org.apache.commons.httpclient.InvalidRedirectLocationException;
import org.apache.commons.httpclient.URIException;
import org.openqa.selenium.*;

import org.apache.log4j.Logger;

import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.remote.*;

import org.parosproxy.paros.core.scanner.*;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.httputils.HtmlContext;
import org.zaproxy.zap.httputils.HtmlContextAnalyser;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;


public class TestSelenium extends AbstractAppParamPlugin {

    public final String DRIVER_PATH = "/Users/mzamith/Downloads/chromedriver";

    private Logger log = Logger.getLogger(this.getClass());
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");


    private WebDriver driver;
    private String site;

    private boolean attackWorked = false;

    public void setUp(HttpMessage msg) throws Exception {

        this.site = msg.getRequestHeader().getURI().toString();

        Proxy proxy = new Proxy();
        proxy.setHttpProxy("localhost:8090");
        proxy.setFtpProxy("localhost:8090");
        proxy.setSslProxy("localhost:8090");
        DesiredCapabilities capabilities = new DesiredCapabilities();
        capabilities.setCapability(CapabilityType.PROXY, proxy);

        System.setProperty("webdriver.chrome.driver", DRIVER_PATH);
        driver = new ChromeDriver();
        this.setDriver(driver);
        driver.manage().timeouts().implicitlyWait(30, TimeUnit.SECONDS);
    }

    public void tearDown(HttpMessage msg) throws Exception {
        driver.close();


    }

    public void tstLoginUser(HttpMessage msg) {

        this.loginUser("tom",  "' OR '1' = '1");


        if (driver.getPageSource().indexOf("Succesfully logged in.") > 0) {
            System.out.println("LOGIN: PASS");

            this.attackWorked = true;


        }else
            System.out.println("LOGIN: FAIL");

    }


    public void loginUser(String user, String password) {
        driver.get(site);

        WebElement link = driver.findElement(By.name("username"));
        link.sendKeys(user);

        link = driver.findElement(By.name("passwd"));
        link.sendKeys(password);

        link = driver.findElement(By.id("submit"));
        link.click();
        //sleep();
    }

    protected WebDriver getDriver() {
        return driver;
    }

    protected void setDriver(WebDriver driver) {
        this.driver = driver;
    }

    protected String getSite() {
        return site;
    }

    protected void setSite(String site) {
        this.site = site;
    }

    private void sleep() {
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.getMessage();
        }
    }

    public void testAll(HttpMessage msg) {
        tstLoginUser(msg);
    }


    @Override
    public int getId() {
        return 45543;
    }

    @Override
    public String getName() {
        return "SeleniumTest";
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


    @Override
    public void scan(HttpMessage msg, String param, String value) {

        this.init(msg, this.getParent());

        try{
            this.setUp(msg);
            this.testAll(msg);
            this.tearDown(msg);
        }catch (Exception e){
            log.error(e.getMessage());
        }

        System.out.println("TEAR DOWN");

        if (this.attackWorked){

            try {

                bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM,
                        this.site, null, "attack",
                        "otherInfo", null, msg);
            }catch (Exception e){
                log.error(e.getMessage());
            }
        }
        System.out.println("TEAR DOWN2");

    }
}