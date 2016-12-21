package org.zaproxy.zap.extension.ascanrules;

import org.apache.log4j.Logger;

import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.remote.*;
import org.openqa.selenium.*;

import org.parosproxy.paros.core.scanner.*;
import org.parosproxy.paros.network.HttpMessage;

import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

import java.util.concurrent.TimeUnit;

/**
 * SQL Injection test using the Selenium Web Driver Tool
 * 19 December 2016
 * @author ngmatos
 */
public class PHPShellInjection extends AbstractAppParamPlugin {

    private Logger log = Logger.getLogger(this.getClass());
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");

    private JSONUtils config;
    private WebDriver driver;
    private String site;
    private boolean attackWorked = false;

    private void setup(HttpMessage msg) throws Exception {

        config = new JSONUtils();
        config.readConfig();

        this.site = msg.getRequestHeader().getURI().toString();

        Proxy proxy = new Proxy();
        proxy.setHttpProxy("localhost:8090");
        proxy.setFtpProxy("localhost:8090");
        proxy.setSslProxy("localhost:8090");
        DesiredCapabilities capabilities = new DesiredCapabilities();
        capabilities.setCapability(CapabilityType.PROXY, proxy);

        System.setProperty("webdriver.chrome.driver", config.getSeleniumDriver());
        setDriver(new ChromeDriver());
        this.setDriver(getDriver());
        getDriver().manage().timeouts().implicitlyWait(200, TimeUnit.MILLISECONDS);
    }

    private void injectShell() {
        driver.get(site);
        WebElement link;

        try {
            if (driver.findElements(By.name(config.getSelectBtn())).size() > 0){
                link = driver.findElement(By.name(config.getSelectBtn()));
                link.sendKeys(config.getShellDir());
                this.sleep();
            }


            if (driver.findElements(By.name(config.getSubmitBtn())).size() > 0){
                link = driver.findElement(By.name(config.getSubmitBtn()));
                link.click();
                this.sleep();
            }
        } catch (Exception e){
            log.error(e.getMessage());
        }

        if (driver.getPageSource().indexOf(config.getUploadSuccess()) > 0) {
            try {
                if (driver.findElements(By.xpath(config.getxPath())).size() > 0) {
                    link = driver.findElement(By.xpath(config.getxPath()));
                    link.click();
                    this.sleep();
                }

                if (driver.findElements(By.name(config.getPassField())).size() > 0){
                    link = driver.findElement(By.name(config.getPassField()));
                    link.sendKeys(config.getPass());
                    link.sendKeys(Keys.RETURN);
                    this.sleep();
                }

                if (driver.findElements(By.id(config.getShellInjected())).size() > 0) {
                    this.attackWorked = true;
                    System.out.println("Found Shell Injection");
                }

            } catch (Exception e) {
                log.error(e.getMessage());
            }
        } else {
            System.out.println("Didn't find shell injection");
        }
    }

    private void tearDown(){
        driver.close();
    }

    private void sleep() {
        try {
            Thread.sleep(1500);
        } catch (InterruptedException e) {
            log.error(e.getStackTrace());
        }
    }

    @Override
    public void scan(HttpMessage httpMessage, String s, String s1) {
        this.init(httpMessage, this.getParent());

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
                log.error(e.getMessage());
                System.out.println(e.getMessage());
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
