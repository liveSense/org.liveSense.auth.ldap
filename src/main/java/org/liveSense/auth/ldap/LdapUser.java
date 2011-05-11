package org.liveSense.auth.ldap;

public class LdapUser {

    String userName;
    String jcrUserName;
    String password;
    
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
