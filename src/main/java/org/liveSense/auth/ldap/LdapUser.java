package org.liveSense.auth.ldap;

import javax.naming.directory.Attributes;

public class LdapUser {

    String userName;
    String jcrUserName;
    String password;
    Attributes attributes;
    
    public Attributes getAttributes() {
		return attributes;
	}
	public void setAttributes(Attributes attributes) {
		this.attributes = attributes;
	}
	public String getUserName() {
        return userName;
    }
    public void setUserName(String userName) {
        this.userName = userName;
    }
    public String getJcrUserName() {
        return jcrUserName;
    }
    public void setJcrUserName(String jcrUserName) {
        this.jcrUserName = jcrUserName;
    }
    public String getPassword() {
        return password;
    }
    public void setPassword(String password) {
        this.password = password;
    }
    
    
}
