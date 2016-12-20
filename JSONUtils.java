package org.zaproxy.zap.extension.ascanrules;

import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.commons.io.IOUtils;

import java.io.File;
import java.io.FileInputStream;

public class JSONUtils {

    private String shellDir;
    private String shellUrl;
    private String selectBtn;
    private String submitBtn;
    private String seleniumDriver;

    public void readConfig() {

        try {
            String jsonTxt = IOUtils.toString(new FileInputStream("/Users/mercurius/Desktop/zap-extensions/src/org/zaproxy/zap/extension/ascanrules/configs.json"));

            JSONObject jsonObject = (JSONObject) JSONSerializer.toJSON(jsonTxt);

            shellDir = getClass().getResource("configs.json").toString();
            shellUrl = (String) jsonObject.get("shellurl");
            selectBtn = (String) jsonObject.get("selectbtn");
            submitBtn = (String) jsonObject.get("submitbtn");
            seleniumDriver = (String) jsonObject.get("seleniumdriver");

        } catch (Exception e) {
            e.getStackTrace();
        }
    }

    public String getShellDir() {
        return shellDir;
    }

    public String getShellUrl() {
        return shellUrl;
    }

    public String getSelectBtn() {
        return selectBtn;
    }

    public String getSubmitBtn() {
        return submitBtn;
    }

    public String getSeleniumDriver() {
        return seleniumDriver;
    }
}
