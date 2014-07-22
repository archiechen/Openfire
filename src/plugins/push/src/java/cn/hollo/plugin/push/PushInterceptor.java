package cn.hollo.plugin.push;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;

import javapns.devices.Device;
import javapns.devices.implementations.basic.BasicDevice;
import javapns.notification.AppleNotificationServerBasicImpl;
import javapns.notification.PushNotificationManager;
import javapns.notification.PushNotificationPayload;
import javapns.notification.PushedNotification;

import org.apache.commons.lang.StringUtils;
import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.openfire.PresenceManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.interceptor.InterceptorManager;
import org.jivesoftware.openfire.interceptor.PacketInterceptor;
import org.jivesoftware.openfire.interceptor.PacketRejectedException;
import org.jivesoftware.openfire.muc.MUCRoom;
import org.jivesoftware.openfire.muc.MultiUserChatManager;
import org.jivesoftware.openfire.muc.MultiUserChatService;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.JID;
import org.xmpp.packet.Message;
import org.xmpp.packet.Packet;
import org.xmpp.packet.Presence;

/**
 * <b>function:</b> send offline msg plugin
 * 
 * @author MZH
 */
public class PushInterceptor implements PacketInterceptor {
	private static final Logger Log = LoggerFactory
			.getLogger(PushInterceptor.class);
	// Hook for intercpetorn
	private InterceptorManager interceptorManager;
	private UserManager userManager;
	private PresenceManager presenceManager;

	public PushInterceptor() {
		interceptorManager = InterceptorManager.getInstance();
		interceptorManager.addInterceptor(this);

		XMPPServer server = XMPPServer.getInstance();
		userManager = server.getUserManager();
		presenceManager = server.getPresenceManager();
	}

	/**
	 * intercept message
	 */
	@Override
	public void interceptPacket(Packet packet, Session session,
			boolean incoming, boolean processed) throws PacketRejectedException {
		if (processed || !(packet instanceof Message) || !incoming)
			return;
		Log.info("Push interceptor for " + packet.toString() + " processed:"
				+ processed + " incoming:" + incoming);
		this.doAction(packet, incoming, processed, session);

	}

	/**
	 * <b>send offline msg from this function </b>
	 */
	private void doAction(Packet packet, boolean incoming, boolean processed,
			Session session) {
		Message message = (Message) packet;
		Log.info("is group? " + (message.getType() == Message.Type.groupchat));
		if (message.getType() == Message.Type.chat) {
			JID recipient = message.getTo();
			// get message
			try {
				// if (recipient.getNode() == null
				// ||
				// !UserManager.getInstance().isRegisteredUser(recipient.getNode()))
				// {
				// // Sender is requesting presence information of an anonymous
				// //throw new UserNotFoundException("Username is null");
				// }

				Presence status = presenceManager.getPresence(userManager
						.getUser(recipient.getNode()));
				if (status == null) { // offline
					String deviceToken = getDeviceToken(recipient.getNode());
					Log.info("Get Device Token is:" + deviceToken);
					if (isApple(deviceToken))
						pns(deviceToken, message.getBody());
				}// end if

			} catch (UserNotFoundException e) {
				Log.warn("Push Error.", e);
			}
		}
		if (message.getType() == Message.Type.groupchat) {
			JID recipient = message.getTo();
			Log.info("recipient node is " + recipient.getNode());
			Log.info("recipient domain is " + recipient.getDomain());
			MultiUserChatManager mucm = XMPPServer.getInstance()
					.getMultiUserChatManager();
			MultiUserChatService service = mucm
					.getMultiUserChatService("conference");
			MUCRoom groupChat = service.getChatRoom(recipient.getNode());
			Collection<JID> members = groupChat.getMembers();
			Log.info("Member Size:" + members.size());
			for (JID member : members) {
				Presence status;
				try {
					status = presenceManager.getPresence(userManager
							.getUser(member.getNode()));
					Log.info("member is " + member.toString()
							+ " and status is "
							+ (status == null ? "offline" : status.toString()));
					if (status == null) { // offline
						String deviceToken = getDeviceToken(member.getNode());
						Log.info("Get Device Token is:" + deviceToken);
						if (isApple(deviceToken))
							pns(deviceToken, message.getBody());
					}// end if
				} catch (UserNotFoundException e) {
					Log.warn("User not found.", e);
				}
			}
			Collection<JID> owners = groupChat.getOwners();
			for (JID owner : owners) {
				Presence status;
				try {
					status = presenceManager.getPresence(userManager
							.getUser(owner.getNode()));
					Log.info("owner is " + owner.toString() + " and status is "
							+ (status == null ? "offline" : status.toString()));
					if (status == null) { // offline
						String deviceToken = getDeviceToken(owner.getNode());
						Log.info("Get Device Token is:" + deviceToken);
						if (isApple(deviceToken))
							pns(deviceToken, message.getBody());
					}// end if

				} catch (UserNotFoundException e) {
					Log.warn("User not found.", e);
				}
			}
		}
	}

	/**
	 * 判断是否苹果
	 * 
	 * @param deviceToken
	 * @return
	 */
	private boolean isApple(String deviceToken) {
		if (deviceToken != null && deviceToken.length() > 0) {
			return true;
		}
		return false;
	}

	public String getDeviceToken(String userId) {
		Log.info("Get Device Token for:" + userId);
		String deviceToken = "";
		String deviceType = "";
		Connection con = null;
		PreparedStatement pstmt = null;
		ResultSet rs = null;
		try {
			con = DbConnectionManager.getConnection();
			pstmt = con
					.prepareStatement("SELECT device_token,device_type FROM ofUser where username = ?");
			pstmt.setString(1, userId);
			rs = pstmt.executeQuery();
			if (rs.next()) {
				deviceToken = rs.getString(1);
				deviceType = rs.getString(2);
				Log.info("Get Device Token is:" + deviceToken
						+ " Device Type is:" + deviceType);
			}
		} catch (SQLException e) {
			Log.error("Get Token error.", e);
		} finally {
			DbConnectionManager.closeConnection(rs, pstmt, con);
		}
		if (deviceType == null) {
			return null;
		}
		return deviceType.toLowerCase().trim().equals("ios") ? deviceToken
				: null;
	}

	public void pns(String token, String msg) {
		String sound = "default";// 铃音
		String certificatePath = JiveGlobals.getProperty(
				"plugin.push.apnsPath", "");
		String certificatePassword = JiveGlobals.getProperty(
				"plugin.push.apnsKey", ""); // 此处注意导出的证书密码不能为空因为空密码会报错
		boolean isProduct = JiveGlobals.getBooleanProperty(
				"plugin.push.isProduct", false);
		try {
			Log.info("push for token:" + token + " and message:" + msg);
			PushNotificationPayload payLoad = new PushNotificationPayload();
			payLoad.addAlert(msg); // 消息内容
			payLoad.addBadge(1); // iphone应用图标上小红圈上的数值
			if (!StringUtils.isBlank(sound)) {
				payLoad.addSound(sound);// 铃音
			}
			PushNotificationManager pushManager = new PushNotificationManager();
			// true：表示的是产品发布推送服务 false：表示的是产品测试推送服务
			pushManager
					.initializeConnection(new AppleNotificationServerBasicImpl(
							certificatePath, certificatePassword, isProduct));
			// 发送push消息
			Device device = new BasicDevice();
			device.setToken(token);
			PushedNotification notification = pushManager.sendNotification(
					device, payLoad, true);
			Log.info("notification is " + notification.isSuccessful());
			pushManager.stopConnection();
		} catch (Exception e) {
			Log.error("Push Error.", e);
		}
	}

}
