package org.zaproxy.zap.extension.ascanrules;


import org.apache.commons.exec.ExecuteException;
import org.apache.log4j.Logger;

import org.json.simple.JSONObject;
import org.json.simple.parser.JSONParser;

import org.openqa.selenium.Alert;
import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.firefox.internal.Streams;
import org.openqa.selenium.remote.*;
import org.openqa.selenium.*;

import org.openqa.selenium.remote.server.handler.WebElementHandler;
import org.parosproxy.paros.core.scanner.*;
import org.parosproxy.paros.network.HttpMessage;

import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

import java.io.FileReader;

import java.util.concurrent.TimeUnit;

/**
 * Created by mercurius on 19/12/16.
 */
public class PHPShellInjection extends AbstractAppParamPlugin {

    private Logger log = Logger.getLogger(this.getClass());
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");

    private String shellDir;
    private String shellUrl;
    private String selectBtn;
    private String submitBtn;
    private String seleniumDriver;
    private WebDriver driver;
    private String site;
    private boolean attackWorked = false;

    private void readConfigs(){
        JSONParser parser = new JSONParser();

        try {

            Object obj = parser.parse(new FileReader("/Users/mercurius/Desktop/zap-extensions/src/org/zaproxy/zap/extension/ascanrules/configs.json"));

            JSONObject jsonObject = (JSONObject) obj;

            shellDir = (String) jsonObject.get("shelldir");
            shellUrl = (String) jsonObject.get("shellurl");
            selectBtn = (String) jsonObject.get("selectbtn");
            submitBtn = (String) jsonObject.get("submitbtn");
            seleniumDriver = (String) jsonObject.get("seleniumdriver");

        } catch (Exception e) {
            log.error(e.getStackTrace());
            System.out.println(e.getStackTrace());
            e.getStackTrace();
        }
    }

    private void setup(HttpMessage msg) throws Exception {

        this.site = msg.getRequestHeader().getURI().toString();

        Proxy proxy = new Proxy();
        proxy.setHttpProxy("localhost:8090");
        proxy.setFtpProxy("localhost:8090");
        proxy.setSslProxy("localhost:8090");
        DesiredCapabilities capabilities = new DesiredCapabilities();
        capabilities.setCapability(CapabilityType.PROXY, proxy);

        System.setProperty("webdriver.chrome.driver", seleniumDriver);
        setDriver(new ChromeDriver());
        this.setDriver(getDriver());
        getDriver().manage().timeouts().implicitlyWait(30, TimeUnit.SECONDS);
    }

    private void injectShell() {
        driver.get(site);

        WebElement link = driver.findElement(By.name(selectBtn));
        link.sendKeys(shellDir);
        this.sleep();

        link = driver.findElement(By.name(submitBtn));
        link.click();
        this.sleep();

        if (driver.getPageSource().indexOf("Upload succesful: ") > 0) {
            this.attackWorked = true;
            System.out.println("Found shell injection");
        } else {
            System.out.println("Didn't find shell injection");
        }
    }

    private void tearDown(){
        driver.close();
    }

    private void sleep() {
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            log.error(e.getStackTrace());
        }
    }

    @Override
    public void scan(HttpMessage httpMessage, String s, String s1) {
        this.init(httpMessage, this.getParent());
        this.readConfigs();

        try {
            this.setup(httpMessage);
            this.injectShell();
            this.tearDown();
        } catch (Exception e) {
            log.error(e.getStackTrace());
            System.out.println(e.getStackTrace());
        }

        if (this.attackWorked) {
            try {
                bingo(org.parosproxy.paros.core.scanner.Alert.RISK_HIGH, org.parosproxy.paros.core.scanner.Alert.CONFIDENCE_MEDIUM,
                        this.site, null, "attack",
                        "otherInfo", null, httpMessage);
            } catch (Exception e) {
                log.error(e.getStackTrace());
                System.out.println(e.getStackTrace());
            }
        }
    }

    @Override
    public int getId() {
        return 235234532;
    }

    @Override
    public String getName() {
        return "PHP Shell Injector";
    }

    @Override
    public String[] getDependency() {
        return new String[0];
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

    public WebDriver getDriver() {
        return driver;
    }

    public void setDriver(WebDriver driver) {
        this.driver = driver;
    }
}
