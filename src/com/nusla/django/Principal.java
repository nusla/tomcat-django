package com.nusla.django;


/**
 * Java security Principal implmentation that represents
 * a user logged in into Drupal and accessing a Tomcat resource, protected
 * by this solution.
 */
public class Principal implements java.security.Principal{
    protected long id;
    protected String accountName;
    protected String fullName;
    protected boolean isActive;


    public Principal(long id, String accountName, String fullName, boolean active){
        this.id = id;
	this.accountName = accountName;
	this.fullName = fullName;
	this.isActive = active;
    }

    /**
     * Returns the unique user identifier assigned to user's record in the database 
     * @return user's login id
     */
    public long getId(){
	return this.id;
    }
    
    /** 
     * @return human readable name of the user
     */   
    public String getFullName(){
	return this.fullName;
    }

    
    /** 
     * @return unique account name in the system
     */   
    public String getName(){
	return this.accountName;
    } 
    
    /** 
     * @return 'false' if user is marked as inactive in the database. Otherwise - 'true'
     */
    public boolean isActive(){
	return this.isActive;
    }

    @Override
    public String toString(){
	StringBuilder sb = new StringBuilder();

	sb.append("id: "); sb.append(this.id); 
	sb.append(", account:"); sb.append(accountName);
	sb.append(", fullName:"); sb.append(fullName);
	sb.append(", active:"); sb.append(isActive);
	
	return (sb.toString());
	/*        return "id: "+ this.id + " account:" + accountName != null ? accountName : "<null>" +
	    " full name:" + fullName != null ? fullName : "<null>" +
	    " active:" + (isActive  ? "true" : "false");*/
    }
}