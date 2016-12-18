package org.zaproxy.zap.extension.ascanrules;

import java.util.concurrent.TimeUnit;

import org.openqa.selenium.*;

import org.apache.log4j.Logger;

import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.remote.*;
import org.openqa.selenium.firefox.*;


import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.core.scanner.Category;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;


public class TestSelenium extends AbstractAppParamPlugin {

    public final String DRIVER_PATH = "/Users/mzamith/Downloads/chromedriver";

    private Logger log = Logger.getLogger(this.getClass());
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");


    private WebDriver driver;
    private String site = "http://localhost:8888/bricks/login-1/";

    public void setUp() throws Exception {
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

    public void tearDown() throws Exception {
        driver.close();
    }

    public void tstLoginUser() {

        sleep();
        this.loginUser("tom", "tom");
        sleep();
        if (driver.getPageSource().indexOf("Succesfully logged in.") > 0)
            System.out.println("LOGIN: PASS");
        else
            System.out.println("LOGIN: FAIL");

        sleep();
        sleep();
    }


    public void loginUser(String user, String password) {
        driver.get(site);

        WebElement link = driver.findElement(By.name("username"));
        link.sendKeys(user);

        link = driver.findElement(By.name("passwd"));
        link.sendKeys(password);

        link = driver.findElement(By.id("submit"));
        link.click();
        sleep();
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

    public void testAll() {
        tstLoginUser();
    }

    public static void main(String[] args) throws Exception {
        TestSelenium test = new TestSelenium();
        test.setUp();
        test.testAll();
        test.tearDown();
    }

    @Override
    public int getId() {
        return 0;
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

    @Override
    public void scan(HttpMessage msg, String param, String value) {
        TestSelenium test = new TestSelenium();

        try{
            test.setUp();
            test.testAll();
            test.tearDown();
        }catch (Exception e){
            log.error(e.getMessage());
        }

    }
}