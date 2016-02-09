package com.nusla.django;

import org.apache.catalina.authenticator.AuthenticatorBase;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import javax.servlet.http.Cookie;

import org.apache.juli.logging.Log;
import org.apache.juli.logging.LogFactory;

import org.apache.catalina.Container;
import org.apache.catalina.Context;
import org.apache.catalina.Engine;
import org.apache.catalina.Host;
import org.apache.catalina.Server;
import org.apache.catalina.Service;
import org.apache.catalina.Realm;
import org.apache.catalina.Session;
import org.apache.catalina.SessionEvent;
import org.apache.catalina.SessionListener;
import org.apache.catalina.connector.Request;
import org.apache.catalina.connector.Response;
import org.apache.catalina.deploy.LoginConfig;
import org.apache.catalina.util.LifecycleSupport;
import org.apache.catalina.Context;
//import org.apache.catalina.Lifecycle;
import org.apache.catalina.LifecycleException;
//import org.apache.catalina.LifecycleListener;

import org.apache.catalina.core.StandardServer;
import org.apache.naming.ContextBindings;

import java.sql.Connection;
import java.sql.Driver;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Base64;
import javax.sql.DataSource;

import javax.servlet.http.HttpServletResponse;
import org.json.simple.JSONObject;
import org.json.simple.JSONValue;
import org.json.simple.parser.ParseException;

public class SessionAuthenticator extends AuthenticatorBase{
    private static Log log = LogFactory.getLog(SessionAuthenticator.class);
    
    protected static final String DJANGO_SESSION_COOKIE        = "sessionid";
    protected static final String DJANGO_SESSION_TABLE         = "django_session";
    protected static final String DJANGO_USER_TABLE            = "auth_user";
    protected static final String DJANGO_SESSION_COL           = "sid";
    protected static final String DJANGO_SECURE_SESSION_COL    = "ssid";
    protected static final String DJANGO_BLOB_UID_FIELD        = "_auth_user_id";

    protected String dataSourceName = null;

    protected String sessionCookie = DJANGO_SESSION_COOKIE;

    protected String loginUrl = null;

    protected boolean localDataSource = false;

    
    public SessionAuthenticator(){
    }


    /**
     * Return the name of the JNDI JDBC DataSource.
     *
     */
    public String getDataSourceName() {
        return dataSourceName;
    }

    /**
     * Set the name of the JNDI JDBC DataSource.
     *
     * @param dataSourceName the name of the JNDI JDBC DataSource
     */
    public void setDataSourceName( String dataSourceName) {
      this.dataSourceName = dataSourceName;
    }


    /**
     * Set to true to cause the datasource to be looked up in the webapp JNDI
     * Context.
     *
     * @param localDataSource the new flag value
     */
    public void setLocalDataSource(boolean localDataSource) {
      this.localDataSource = localDataSource;
    }

    /**
     * Return if the datasource will be looked up in the webapp JNDI Context.
     */
    public boolean getLocalDataSource() {
        return localDataSource;
    }
    

    /**
     * Where to redirect if the user is not logged in
     */
    public void setLoginUrl(String url){
	loginUrl = url;
    }

    /**
     * Iterates over cookies and finds the first match that looks
     * like a Drupal login cookie. Usually it is SESSxxxxxxxxx
     * @param request - the HTTP request being serviced
     * @return matching cookie or NULL
     */
    protected Cookie getSessionCookie(Request request){
        Cookie cookie = null;
        Cookie cookies[] = request.getCookies();
        if (cookies == null)
            cookies = new Cookie[0];
        for (int i = 0; i < cookies.length; i++) {
	    cookie = cookies[i];
	    String name = cookie.getName();

	    if (name.equals(sessionCookie))
		return cookie;
        }

	return null;
    }

    protected String getAuthMethod(){
	return "DJANGO";
    }

    /**
     * AuthenticationBase method that is called to validate user's credentials
     *
     * @param request Request we are processing
     * @param response Response we are creating
     * @param config    Login configuration describing how authentication
     *              should be performed
     *
     * @exception IOException if an input/output error occurs
     */
    public boolean authenticate(Request request,
				   HttpServletResponse response,
				   LoginConfig config) throws IOException{

	if (containerLog.isDebugEnabled())
            containerLog.debug(" Checking for SSO cookie");

	Cookie cookie = getSessionCookie(request);

	if (cookie != null){
	    if (containerLog.isDebugEnabled())
		containerLog.debug("Found SSO cookie "+cookie.getName());

	    try{
		Principal principal = loadPrincipalBySession(cookie.getValue());
		if (principal != null){
		    if (containerLog.isDebugEnabled()){
			containerLog.debug("Got SSO user => " + principal);	
		    }
		    register(request, response, principal, getAuthMethod(), principal.getName(), cookie.getValue());
		    return true;
		}else{
		    if (containerLog.isDebugEnabled()){
			containerLog.debug("Unable to find session and user for the SSO cookie value (SESSION ID = " + cookie.getValue() + ")");	
		    }
		}
	    }catch(Exception e){
		containerLog.error("Failed to load principal from Drupal session (SESSION ID = " + cookie.getValue() + ")", e);
	    }
	}else{
	    if (containerLog.isDebugEnabled()){
		containerLog.debug(" SSO cookie is not present");	
	    }
	}
       

	/// User is anonymous or authentication failed - redirect to the login page
	/// if there is one
	if (this.loginUrl != null){
	    if (containerLog.isDebugEnabled()){
		containerLog.debug("Redirecting user to \""+this.loginUrl+"\"");	
	    }
	    response.sendRedirect(this.loginUrl);	    
	}
	return false;
    }

    protected Server getServer() {
        Container c = container;
        if (c instanceof Context) {
            c = c.getParent();
        }
        if (c instanceof Host) {
            c = c.getParent();
        }
        if (c instanceof Engine) {
            Service s = ((Engine)c).getService();
            if (s != null) {
                return s.getServer();
            }
        }
        return null;
    }

    /**
     * Open the specified database connection.
     *
     * @return Connection to the database
     */
    protected Connection open() {

        try {
            javax.naming.Context context = null;
            if (localDataSource) {
                context = ContextBindings.getClassLoader();
                context = (javax.naming.Context) context.lookup("comp/env");
            } else {
                context = getServer().getGlobalNamingContext();
            }
            DataSource dataSource = (DataSource)context.lookup(dataSourceName);
	    return dataSource.getConnection();
        } catch (Exception e) {
            // Log the problem for posterity
	    if (localDataSource)
		containerLog.error("SessionAuthentocator.exception - local data source", e);
	    else
		containerLog.error("SessionAuthentocator.exception - global data source", e);
        }  
        return null;
    }


    /**
     * Close the specified database connection.
     *
     * @param dbConnection The connection to be closed
     */
    protected void close(Connection dbConnection) {

        // Do nothing if the database connection is already closed
        if (dbConnection == null)
            return;

        // Commit if not auto committed
        try {
            if (!dbConnection.getAutoCommit()) {
                dbConnection.commit();
            }            
        } catch (SQLException e) {
            containerLog.error("Exception committing connection before closing:", e);
        }

        // Close this database connection, and log any errors
        try {
            dbConnection.close();
        } catch (SQLException e) {
            containerLog.error("SesionAuthenticator.close", e); // Just log it here
        }

    }

    /**
     * Parse the Django session data and extract the UID
     */
    protected String extractUidFromBlob(String blob) throws ParseException{
        byte [] decoded = Base64.getDecoder().decode(blob);

        String str = new String(decoded, StandardCharsets.UTF_8);

        int colPos = str.indexOf(':');
        if (colPos < 0)
            return null;

        String json = str.substring(colPos + 1);

        JSONObject parsed = (JSONObject)JSONValue.parseWithException(json);
        return (String)parsed.get(DJANGO_BLOB_UID_FIELD);        
    }
    
    
    protected PreparedStatement createSessionStatement(Connection dbConnection,  String sessionId) throws SQLException {
	StringBuffer sb = new StringBuffer("SELECT ");
	
	sb.append(" session_key, session_data, expire_date ");
	sb.append(" FROM ");

	sb.append(DJANGO_SESSION_TABLE); sb.append(" s ");

	sb.append(" WHERE s.session_key = ? ");
	
	if(containerLog.isDebugEnabled()) {
	    containerLog.debug("Session lookup query: " + sb.toString());
	}
	
	PreparedStatement stmt = dbConnection.prepareStatement(sb.toString());

	stmt.setString(1, sessionId);
	return stmt;
    }
    
    protected PreparedStatement createUserLookupStatement(Connection dbConnection,  String uid) throws SQLException {
	StringBuffer sb = new StringBuffer("SELECT ");
	
	String query = " select " +
                "	u.username, u.first_name, u.last_name, u.is_active " +
                "from " +
                "	auth_user u " +
                "where " +
                "       u.id = ?";
	sb.append(" FROM ");

	sb.append(DJANGO_SESSION_TABLE); sb.append(" s ");

	sb.append(" WHERE s.session_key = ? ");
	
	if(containerLog.isDebugEnabled()) {
	    containerLog.debug("Session lookup query: " + sb.toString());
	}
	
	PreparedStatement stmt = dbConnection.prepareStatement(sb.toString());

	stmt.setString(1, uid);
	return stmt;
    }
    
    /**
     * Lookup and load the principal by Django session
     */
    protected Principal loadPrincipalBySession(String sessionId) throws SQLException, ParseException{
	Principal p = null;
	Connection c = open();

	if (c == null)
	    return null;
	
	try{
	    PreparedStatement stmt = null;
	    ResultSet rs = null;
	
	    stmt = createSessionStatement(c,  sessionId);
            rs = stmt.executeQuery();

	    if (rs.next()) {
		String key = rs.getString(1);
		String data = rs.getString(2);
		String exp = rs.getString(3);

		if(containerLog.isDebugEnabled()) {
		    containerLog.debug("Found session: {key:" + key + ", data:"+data + ", mail:" + exp + "}");
		}
                
		if (data.length() > 0){
                    String strUid = this.extractUidFromBlob(data);
                    if (strUid.length() > 0){
                        PreparedStatement ustmt = createUserLookupStatement(c, strUid);
                        ResultSet urs = ustmt.executeQuery();
                        
                        String username = null;
                        String fullName = null;
                            
                        if(urs.next()){
                            username = urs.getString(1);
                            String first = urs.getString(2);
                            String last = urs.getString(3);
                            
                            fullName = first;
                            if (fullName == null)
                                fullName = "";
                            
                            if (last != null)
                                fullName += " " + last;
                        }
                        
                        long uid = Long.parseLong(strUid);
                        p = new Principal(
                                        uid,
                                        urs.getString(1),
                                        fullName,
                                        urs.getBoolean(4)
                        );

			if(containerLog.isDebugEnabled()) {
			    containerLog.debug("Got principal : " + p);
			}
                    }
                }
            }
	}finally{
	    close(c);
	}
	
	return p;
    }
}