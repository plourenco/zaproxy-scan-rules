package org.zaproxy.zap.extension.ascanrules;

import org.parosproxy.paros.core.scanner.AbstractAppParamPlugin;
import org.parosproxy.paros.network.HttpMessage;

public class TestScript extends AbstractAppParamPlugin {

    @Override
    public void scan(HttpMessage httpMessage, String s, String s1) {

    }

    @Override
    public int getId() {
        return 0;
    }

    @Override
    public String getName() {
        return "TestPlugin";
    }

    @Override
    public String[] getDependency() {
        return new String[0];
    }

    @Override
    public String getDescription() {
        return null;
    }

    @Override
    public int getCategory() {
        return 0;
    }

    @Override
    public String getSolution() {
        return null;
    }

    @Override
    public String getReference() {
        return null;
    }

    @Override
    public void init() {

    }
}