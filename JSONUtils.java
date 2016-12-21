package org.zaproxy.zap.extension.ascanrules;

import net.sf.json.JSONArray;
import net.sf.json.JSONObject;
import net.sf.json.JSONSerializer;
import org.apache.commons.io.IOUtils;
import org.apache.commons.io.output.StringBuilderWriter;

import java.io.File;
import java.io.FileInputStream;
import java.util.ArrayList;
import java.util.List;

public class JSONUtils {

    private String shellDir;
    private String shellUrl;
    private String selectBtn;
    private String submitBtn;
    private String seleniumDriver;
    private String uploadSuccess;
    private String passField;
    private String pass;
    private String shellInjected;
    private String xPath;
    private List<String> sqlSuccess;

    public void readConfig() {

        try {
            String jsonTxt = IOUtils.toString(new FileInputStream("/Users/mercurius/Desktop/zap-extensions/src/org/zaproxy/zap/extension/ascanrules/configs.json"));

            JSONObject jsonObject = (JSONObject) JSONSerializer.toJSON(jsonTxt);

            shellDir = (String) jsonObject.get("shelldir");
            shellUrl = (String) jsonObject.get("shellurl");
            selectBtn = (String) jsonObject.get("selectbtn");
            submitBtn = (String) jsonObject.get("submitbtn");
            seleniumDriver = (String) jsonObject.get("seleniumdriver");
            uploadSuccess = (String) jsonObject.get("uploadinject");
            passField = (String) jsonObject.get("passfield");
            pass = (String) jsonObject.get("pass");
            shellInjected = (String) jsonObject.get("succshell");
            xPath = (String) jsonObject.get("xpath");
            JSONArray jArray = jsonObject.getJSONArray("sqlSuccess");

            System.out.print (jArray.get(0));

            sqlSuccess = new ArrayList<>();

            if (jArray != null) {
                for (int i = 0; i < jArray.size(); i++){
                    sqlSuccess.add(jArray.getString(i));

                    System.out.print(sqlSuccess.get(i));
                }
            }

        } catch (Exception e) {
            System.out.println("ERROR PARSING JSON");
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

    public String getPass() {
        return pass;
    }

    public String getxPath() {
        return xPath;
    }

    public String getShellInjected() {
        return shellInjected;
    }

    public String getSubmitBtn() {
        return submitBtn;
    }

    public String getPassField() {
        return passField;
    }

    public String getUploadSuccess() {
        return uploadSuccess;
    }

    public String getSeleniumDriver() {
        return seleniumDriver;
    }

    public List<String> getSQLSuccess() { return sqlSuccess; }
}
