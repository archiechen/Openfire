package org.jivesoftware.openfire.auth;

import java.net.HttpURLConnection;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.URLEncoder;
import java.io.InputStream;
import java.net.URL;
import java.net.URLConnection;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.SQLException;
import java.sql.Types;

import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.user.User;
import org.jivesoftware.openfire.user.UserAlreadyExistsException;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.jivesoftware.util.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.json.JSONObject;

/**
 * The RESTFul auth provider allows you to authenticate users against any
 * database that you can connect to with Restful. It can be used along with the
 * {@link HybridAuthProvider hybrid} auth provider, so that you can also have
 * XMPP-only users that won't pollute your external data.
 * <p>
 * 
 * To enable this provider, set the following in the system properties:
 * <ul>
 * <li>
 * <tt>provider.auth.className = org.jivesoftware.openfire.auth.RESTFulCAuthProvider</tt>
 * </li>
 * </ul>
 * 
 * You'll also need to set your RESTFul url:
 * 
 * <ul>
 * <li><tt>restfulProvider.url = http://localhost:5000/xmppauth</tt></li>
 * </ul>
 * 
 * 
 * The passwordType setting tells Openfire how the password is stored. Setting
 * the value is optional (when not set, it defaults to "plain"). The valid
 * values are:
 * <ul>
 * <li>{@link PasswordType#plain plain}
 * <li>{@link PasswordType#md5 md5}
 * <li>{@link PasswordType#sha1 sha1}
 * <li>{@link PasswordType#sha256 sha256}
 * <li>{@link PasswordType#sha512 sha512}
 * </ul>
 * 
 * @author David Snopek
 */
public class RESTFulAuthProvider implements AuthProvider {

	private static final Logger Log = LoggerFactory
			.getLogger(RESTFulAuthProvider.class);

	private static final String UPDATE_TOKEN = "UPDATE ofUser SET device_token=?,device_type=? WHERE username=?";;

	private String connectionString;
	private PasswordType passwordType;

	/**
	 * Constructs a new REST authentication provider.
	 */
	public RESTFulAuthProvider() {
		// Convert XML based provider setup to auth url
		Log.info("REST AUTH PROVIDER(version 0.21) IS loading....");

		JiveGlobals.migrateProperty("restfulProvider.url");

		connectionString = JiveGlobals.getProperty("restfulProvider.url");

		Log.info("REST AUTH url:" + connectionString);

		passwordType = PasswordType.plain;
	}

	public void authenticate(String username, String password)
			throws UnauthorizedException {
		Log.info("100 line, authenticate was called with username:" + username
				+ " password:" + password);
		if (username == null || password == null) {
			throw new UnauthorizedException();
		}
		username = username.trim().toLowerCase();
		if (username.contains("@")) {
			// Check that the specified domain matches the server's domain
			int index = username.indexOf("@");
			String domain = username.substring(index + 1);
			if (domain.equals(XMPPServer.getInstance().getServerInfo()
					.getXMPPDomain())) {
				username = username.substring(0, index);
			} else {
				// Unknown domain. Return authentication failed.
				throw new UnauthorizedException();
			}
		}
		try {
			verifyPassword(username, password);
		} catch (Exception e) {
			throw new UnauthorizedException();
		}
	}

	public void authenticate(String username, String token, String digest)
			throws UnauthorizedException {

		Log.info("140 line:username:" + username + " password:" + token);
		if (passwordType != PasswordType.plain) {
			throw new UnsupportedOperationException(
					"Digest authentication not supported for "
							+ "password type " + passwordType);
		}
		if (username == null || token == null || digest == null) {
			throw new UnauthorizedException();
		}
		username = username.trim().toLowerCase();
		if (username.contains("@")) {
			// Check that the specified domain matches the server's domain
			int index = username.indexOf("@");
			String domain = username.substring(index + 1);
			if (domain.equals(XMPPServer.getInstance().getServerInfo()
					.getXMPPDomain())) {
				username = username.substring(0, index);
			} else {
				// Unknown domain. Return authentication failed.
				throw new UnauthorizedException();
			}
		}
		String password;
		try {
			verifyPassword(username, token);
		} catch (UserNotFoundException unfe) {
			throw new UnauthorizedException();
		}

		// Got this far, so the user must be authorized.
		createUser(username,null,null);
	}

	public boolean isPlainSupported() {
		// If the auth SQL is defined, plain text authentication is supported.
		return (connectionString != null);
	}

	public boolean isDigestSupported() {
		// The auth SQL must be defined and the password type is supported.
		return (connectionString != null && passwordType == PasswordType.plain);
	}

	public String getPassword(String username) throws UserNotFoundException,
			UnsupportedOperationException {

		throw new UnsupportedOperationException();

	}

	public void setPassword(String username, String password)
			throws UserNotFoundException, UnsupportedOperationException {

		throw new UnsupportedOperationException();

	}

	public boolean supportsPasswordRetrieval() {
		return (passwordType == PasswordType.plain);
	}

	/**
	 * Returns the value of the password field. It will be in plain text or
	 * hashed format, depending on the password type.
	 * 
	 * @param username
	 *            user to retrieve the password field for
	 * @return the password value.
	 * @throws UserNotFoundException
	 *             if the given user could not be loaded.
	 */
	private boolean verifyPassword(String username, String password)
			throws UserNotFoundException {
		Log.info("RESTFul auth with:" + username + " password:" + password);
		if (username.contains("@")) {
			// Check that the specified domain matches the server's domain
			int index = username.indexOf("@");
			String domain = username.substring(index + 1);
			if (domain.equals(XMPPServer.getInstance().getServerInfo()
					.getXMPPDomain())) {
				username = username.substring(0, index);
			} else {
				// Unknown domain.
				throw new UserNotFoundException();
			}
		}
		try {
			String url = connectionString;
			String charset = "UTF-8";
			String checkToken = "12345shangshandalaohu";
			// ...
			String query = String.format("username=%s&checktoken=%s",
					URLEncoder.encode(username, charset),
					URLEncoder.encode(checkToken, charset));

			URLConnection connection = new URL(url + "?" + query)
					.openConnection();
			String myCookie = "session=" + password;
			System.err.println("RESTFul AUTH WITH:" + username + " cookie:"
					+ myCookie);
			Log.info("RESTFul AUTH WITH:" + username + " cookie:" + myCookie);
			connection.setRequestProperty("Cookie", myCookie);
			connection.setRequestProperty("Accept-Charset", charset);
			InputStream response = connection.getInputStream();
			BufferedReader reader = new BufferedReader(new InputStreamReader(
					response, charset));
			 
			String result = reader.readLine();
			Log.info("HolloGo Server Response:"+result);
			JSONObject jo = new JSONObject(result);
			String deviceToken = jo.getString("device_token");
			String deviceType = jo.getString("device_type");
			createUser(username,deviceToken,deviceType);
			return true;
		} catch (Exception e) {
			Log.error("Exception in RESTFulAuthProvider", e);
			throw new UserNotFoundException();
		}

	}

	private void setPasswordValue(String username, String password)
			throws UserNotFoundException {
		Log.info("setPasword value was called:usnermame:" + username
				+ " password:" + password);
		if (username.contains("@")) {
			// Check that the specified domain matches the server's domain
			int index = username.indexOf("@");
			String domain = username.substring(index + 1);
			if (domain.equals(XMPPServer.getInstance().getServerInfo()
					.getXMPPDomain())) {
				username = username.substring(0, index);
			} else {
				// Unknown domain.
				throw new UserNotFoundException();
			}
		}
		try {

			if (passwordType == PasswordType.md5) {
				password = StringUtils.hash(password, "MD5");
			} else if (passwordType == PasswordType.sha1) {
				password = StringUtils.hash(password, "SHA-1");
			} else if (passwordType == PasswordType.sha256) {
				password = StringUtils.hash(password, "SHA-256");
			} else if (passwordType == PasswordType.sha512) {
				password = StringUtils.hash(password, "SHA-512");
			}

		} catch (Exception e) {
			Log.error("Exception in RESTFulAuthProvider", e);
			throw new UserNotFoundException();
		} finally {

		}

	}

	/**
	 * Indicates how the password is stored.
	 */
	@SuppressWarnings({ "UnnecessarySemicolon" })
	// Support for QDox Parser
	public enum PasswordType {

		/**
		 * The password is stored as plain text.
		 */
		plain,

		/**
		 * The password is stored as a hex-encoded MD5 hash.
		 */
		md5,

		/**
		 * The password is stored as a hex-encoded SHA-1 hash.
		 */
		sha1,

		/**
		 * The password is stored as a hex-encoded SHA-256 hash.
		 */
		sha256,

		/**
		 * The password is stored as a hex-encoded SHA-512 hash.
		 */
		sha512;
	}

	/**
	 * Checks to see if the user exists; if not, a new user is created.
	 * 
	 * @param username
	 *            the username.
	 */
	private static void createUser(String username,String deviceToken,String deviceType) {
		// See if the user exists in the database. If not, automatically create
		// them.
		UserManager userManager = UserManager.getInstance();
		try {
			userManager.getUser(username);
			updateToken(username,deviceToken,deviceType);
		} catch (UserNotFoundException unfe) {
			try {
				Log.debug("RESTFulAuthProvider: Automatically creating new user account for "
						+ username);
				UserManager.getUserProvider().createUser(username,
						StringUtils.randomString(8), null, null);
				updateToken(username,deviceToken,deviceType);
			} catch (UserAlreadyExistsException uaee) {
				// Ignore.
				Log.warn("RESTFulAuthProvider Warning.",uaee);
			} catch (UserNotFoundException e) {
				// Ignore.
				Log.warn("RESTFulAuthProvider Warning.",e);
			}
		}
	}
	
	private static void updateToken(String username,String deviceToken,String deviceType) throws UserNotFoundException{
		Connection con = null;
		PreparedStatement pstmt = null;
        try {
            con = DbConnectionManager.getConnection();
            pstmt = con.prepareStatement(UPDATE_TOKEN);
            if (deviceToken == null || deviceToken.matches("\\s*")) {
            	pstmt.setNull(1, Types.VARCHAR);
            } 
            else {
            	pstmt.setString(1, deviceToken);
            }
            pstmt.setString(2, deviceType);
            pstmt.setString(3, username);
            pstmt.executeUpdate();
        }
        catch (SQLException sqle) {
            throw new UserNotFoundException(sqle);
        }
        finally {
            DbConnectionManager.closeConnection(pstmt, con);
        }
	}
}
