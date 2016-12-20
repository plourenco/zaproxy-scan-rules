package org.zaproxy.zap.extension.ascanrules;

import java.util.List;
import java.util.concurrent.TimeUnit;

import org.openqa.selenium.*;

import org.apache.log4j.Logger;

import org.openqa.selenium.chrome.ChromeDriver;
import org.openqa.selenium.remote.*;

import org.parosproxy.paros.core.scanner.*;
import org.parosproxy.paros.core.scanner.Alert;
import org.parosproxy.paros.network.HttpMessage;
import org.zaproxy.zap.extension.selenium.Browser;
import org.zaproxy.zap.extension.selenium.ExtensionSelenium;
import org.zaproxy.zap.model.Vulnerabilities;
import org.zaproxy.zap.model.Vulnerability;

/**
 * SQL Injection test using the Sellenium Web Driver Tool
 * 19 December 2016
 * @author mzamith
 */
public class TestSelenium extends AbstractAppParamPlugin {

    //Required for the Chrome Driver tool
    private static Vulnerability vuln = Vulnerabilities.getVulnerability("wasc_8");
    private JSONUtils config;

    /**
     * generic one-line comment. Various RDBMS Documentation suggests that this
     * syntax works with almost every single RDBMS considered here
     */
    public final String SQL_ONE_LINE_COMMENT = " -- ";

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
    private Logger log = Logger.getLogger(this.getClass());
    private WebDriver driver;
    private String site;

    /**
     * Sets up the Selemium test with the necessary components
     * This method creates a new proxy object and also a new Chrome Driver object
     *
     * @param  msg  message from the scan ZAP method. Allows to retrieve the inserted URI
     */
    public void setUp(HttpMessage msg) throws Exception {

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
        driver = new ChromeDriver();
        this.setDriver(driver);
        driver.manage().timeouts().implicitlyWait(1, TimeUnit.SECONDS);
    }

    /**
     * Tears down the test, closing the browser window
     */
    public void tearDown() throws Exception {
        driver.close();
    }

    /**
     * Tests a User login.
     * The test is successful if a predetermined message appears on the screen.
     *
     * @param  value  input value given by the ZAP scan method
     * @param  msg  Http message from the scan ZAP method.
     */
    public void tstLoginUser(String value, HttpMessage msg) {

        System.out.print(driver.getTitle());

        driver.get(site); //Open Chrome browser

        for (int i = 0; i < this.SQL_LOGIC_OR_TRUE.length; i++){ //go through all the injection strings

            HttpMessage msg2 = getNewMsg();
            String sqlBooleanAndTrueValue = SQL_LOGIC_OR_TRUE[i];

            //sleep(2);

            this.loginUser(value,  sqlBooleanAndTrueValue); //attempt to log in

            boolean sqlInjectionFound = false;

            //sleep(2);

            //Success if the success message is displayed
            for(String test : config.getSQLSuccess()) {
                if (driver.getPageSource().indexOf(test) > 0) {

                    System.out.println("LOGIN: PASS");

                    bingo(Alert.RISK_HIGH, Alert.CONFIDENCE_MEDIUM, getName(), getDescription(),
                            this.site, //url
                            value, sqlBooleanAndTrueValue,
                            "extra info", getSolution(), "", msg2);

                    sqlInjectionFound = true;
                    break;

                } else
                    System.out.println("LOGIN: FAIL");
            }

            if (sqlInjectionFound) break;
        }
    }

    /**
     * Attempts a login by filling in a password and text type input fields
     *
     * @param  user  username for login attempt
     * @param  password  password for login attempt
     */
    public void loginUser(String user, String password) {

        List<WebElement> textInputs = null;
        WebElement passwordInput = null;


        if(!driver.findElements(By.cssSelector("input[type='password']")).isEmpty()) {
            passwordInput = driver.findElement(By.cssSelector("input[type='password']"));
        }
        //find password input

        if(!driver.findElements(By.cssSelector("input[type='text']")).isEmpty()){
            textInputs = driver.findElements(By.cssSelector("input[type='text']")); // find text inputs
        }

        if (passwordInput != null && textInputs != null){
            for (int i = 0; i < textInputs.size(); i++){
                textInputs.get(i).sendKeys(user);
            }
            passwordInput.sendKeys(password);

            if( !driver.findElements(By.cssSelector("input[type='submit']")).isEmpty()){
                WebElement submitButton = driver.findElement(By.cssSelector("input[type='submit']"));
                submitButton.click(); //submit form
            }
        }
        //sleep(1);


    }

    /**
     * UtiliTy method for testing
     *
     * @param  seconds  number of seconds for sleep
     */
    private void sleep(int seconds) {
        try {
            Thread.sleep(seconds * 1000);
        } catch (InterruptedException e) {
            e.getMessage();
        }
    }


    /**
     * GETTERS AND SETTERS
     */
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

    /**
     * NECESSARY METHODS FOR ZAP PLUGIN
     */
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


    @Override
    public void scan(HttpMessage msg, String param, String value) {

        this.init(msg, this.getParent());

        try{
            this.setUp(msg);
            this.tstLoginUser(value, msg);
            this.tearDown();
        }catch (Exception e){
            e.printStackTrace();
        }

    }
}