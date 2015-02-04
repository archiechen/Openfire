package cn.hollo.plugin.push;

import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Collection;
import java.util.HashMap;
import java.util.Iterator;
import java.util.concurrent.atomic.AtomicInteger;

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
import org.jivesoftware.openfire.muc.*;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.*;

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
    private MultiUserChatService mucService;
    private HashMap<String,AtomicInteger> offlineCounter;

	public PushInterceptor() {
		interceptorManager = InterceptorManager.getInstance();
		interceptorManager.addInterceptor(this);

		XMPPServer server = XMPPServer.getInstance();
		userManager = server.getUserManager();
		presenceManager = server.getPresenceManager();
        offlineCounter = new HashMap<String, AtomicInteger>();
        mucService = XMPPServer.getInstance()
                .getMultiUserChatManager()
                .getMultiUserChatService("conference");
	}

	/**
	 * intercept message
	 */
	@Override
    public void interceptPacket(Packet packet, Session session, boolean incoming, boolean processed)
            throws PacketRejectedException
    {
        if ((processed) || (!incoming)) {
            return;
        }
        if ((packet instanceof Message)) {
            Log.info("Interceptor for " + packet.toString() + " processed:" + processed + " incoming:" + incoming + " instance of " + packet
                    .getClass());
            Message message = (Message) packet;
            if(message.getType()== Message.Type.normal){
                if(message.getChildElement("x","jabber:x:conference")!=null){
                    JID groupJid = message.getFrom();

                    MUCRoom groupChat = mucService.getChatRoom(groupJid.getNode());

                    if (groupChat != null) {
                        MUCRole role = groupChat.getRole();
                        try {
                            groupChat.addOwner(message.getTo(), role);
                            Log.info("Add owner " + message.getTo() + " to room " + groupJid.getNode());
                        } catch (ForbiddenException e) {
                            Log.error("Add owner error. " + message.getTo().getNode(), e);
                        }
                    }
                }
            }else {
                doAction(packet, incoming, processed, session);
            }
        }
        if (packet instanceof Presence) {
            Presence p = (Presence)packet;
            Log.info("Interceptor for " + packet.toString() + " processed:" + processed + " incoming:" + incoming + " instance of " + packet
                    .getClass());
            //加入群聊房间
            if (p.getExtension("x", "http://jabber.org/protocol/muc") != null) {
                JID groupJid = p.getTo();

                MUCRoom groupChat = mucService.getChatRoom(groupJid.getNode());

                if (groupChat != null) {
                    Presence np = new Presence();
                    np.setFrom(groupJid.asBareJID());
                    np.setTo(p.getFrom());
                    PacketExtension extension = new PacketExtension("members", "http://hollo.cn/muc/memberlist");

                    Collection members = groupChat.getMembers();
                    JID member;
                    for (Iterator localIterator = members.iterator(); localIterator.hasNext();  ) { member = (JID)localIterator.next();
                        if (member.getNode() != null)
                        {
                            if (member.getNode().equals(p.getFrom().getNode())) {
                                Log.info("Already in members. " + p.getFrom());
                            }
                            extension.getElement().addElement("member").setText(member.getNode());
                        }
                    }

                    Collection<JID> owners = groupChat.getOwners();
                    for (JID owner : owners) {
                        if (owner.getNode().equals(p.getFrom().getNode())) {
                            Log.info("Already in owners. " + p.getFrom());
                        }
                        extension.getElement().addElement("member").setText(owner.getNode());
                    }

                    np.addExtension(extension);
                    XMPPServer.getInstance().getPacketRouter().route(np);
                    Log.info("response members:" + np.toString());
                }
            }

            if ((p.getStatus() != null) && (p.getStatus().equals("logout"))) {
                String userId = p.getFrom().getNode();
                Log.info(userId + " logout.");
                Connection con = null;
                PreparedStatement pstmt = null;
                try {
                    con = DbConnectionManager.getConnection();
                    pstmt = con.prepareStatement("UPDATE ofUser SET device_token=? WHERE username=?");
                    pstmt.setNull(1, 12);
                    pstmt.setString(2, userId);
                    pstmt.executeUpdate();
                }
                catch (SQLException sqle) {
                    Log.error("Logout error. " + userId, sqle);
                }
                finally {
                    DbConnectionManager.closeConnection(pstmt, con);
                }
            }

            if ((p.getStatus() != null) && (p.getStatus().equals("exit"))) {
                String userId = p.getFrom().getNode();
                Log.info(userId + " exit.");
                JID groupJid = p.getTo();

                MUCRoom groupChat = mucService.getChatRoom(groupJid.getNode());

                Collection<JID> owners = groupChat.getOwners();
                if(owners.size()<=1){
                    groupChat.destroyRoom(p.getFrom(),"Last owner leave.");
                    Log.info("Room destroy.");
                }else{
                    MUCRole member = groupChat.getOccupantByFullJID(p.getFrom());
                    if(member!=null) {
                        Log.info("User Address of Room is " + member.getUserAddress());
                        try {
                            groupChat.addNone(p.getFrom(), member);
                            Log.info("Removed member " + userId);
                        } catch (ForbiddenException e) {
                            Log.error("Exit room error.",e);
                        } catch (ConflictException e) {
                            Log.error("Exit room error.",e);
                        }
                    }else {
                        Log.info("Occupant not found for " + p.getFrom().toString());
                    }
                }

            }
        }
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
				Presence status = presenceManager.getPresence(userManager
						.getUser(recipient.getNode()));
                Log.info(recipient.getNode()+ " status is " + (status == null ? "offline" : status.toString()));
				if (status == null) { // offline
					String deviceToken = getDeviceToken(recipient.getNode());
					Log.info("Get Device Token is:" + deviceToken);
					if (isApple(deviceToken))
                        if(offlineCounter.get(recipient.getNode())!=null){
                            offlineCounter.get(recipient.getNode()).addAndGet(1);
                        }else{
                            offlineCounter.put(recipient.getNode(),new AtomicInteger(1));
                        }
						pns(deviceToken, message.getBody(),offlineCounter.get(recipient.getNode()).get());
				}else{
                    offlineCounter.remove(recipient.getNode());
                }// end if

			} catch (UserNotFoundException e) {
				Log.warn("Push Error.", e);
			}
		}
		if (message.getType() == Message.Type.groupchat) {
			JID recipient = message.getTo();
			Log.info("recipient node is " + recipient.getNode());
			Log.info("recipient domain is " + recipient.getDomain());
			MUCRoom groupChat = mucService.getChatRoom(recipient.getNode());
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
						if (isApple(deviceToken)) {
                            if (offlineCounter.get(member.getNode()) != null) {
                                offlineCounter.get(member.getNode()).addAndGet(1);
                            } else {
                                offlineCounter.put(member.getNode(), new AtomicInteger(1));
                            }
                            pns(deviceToken, message.getBody(), offlineCounter.get(member.getNode()).get());
                        }
					}else{
                        offlineCounter.remove(member.getNode());
                    }// end if
				} catch (UserNotFoundException e) {
					Log.warn("User not found.", e);
				}
			}
			Collection<JID> owners = groupChat.getOwners();
            Log.info("Owner Size:" + owners.size());
			for (JID owner : owners) {
				Presence status;
				try {
					status = presenceManager.getPresence(userManager
							.getUser(owner.getNode()));
					Log.info("owner is " + owner.toString() + " and status is "
							+ (status == null ? "offline" : status.toString()));
					if (status == null) { // offline
                        String deviceToken = getDeviceToken(owner.getNode());
						if (isApple(deviceToken)) {
                            if (offlineCounter.get(owner.getNode()) != null) {
                                offlineCounter.get(owner.getNode()).addAndGet(1);
                            } else {
                                offlineCounter.put(owner.getNode(), new AtomicInteger(1));
                            }
                            pns(deviceToken, message.getBody(), offlineCounter.get(owner.getNode()).get());
                        }
					}else{
                        offlineCounter.remove(owner.getNode());
                    }// end if

				} catch (UserNotFoundException e) {
					Log.warn("User not found "+owner.getNode(), e);
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

	public void pns(String token, String msg, int badge) {
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
			payLoad.addBadge(badge); // iphone应用图标上小红圈上的数值
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

    public static void main(String[] args){
        String sound = "default";// 铃音
        String certificatePath = "/Users/Archie/Downloads/new_dev_push.p12";
        String certificatePassword = "pinche"; // 此处注意导出的证书密码不能为空因为空密码会报错
        boolean isProduct = true;
        String msg="This is testing.";
        int badge = 1;
        String token = "814631ce48c37b5cd55a6092ee3bf9b027f80d675856cdf0e9011d32c9cd49dd";
        try {
            PushNotificationPayload payLoad = new PushNotificationPayload();
            payLoad.addAlert(msg); // 消息内容
            payLoad.addBadge(badge); // iphone应用图标上小红圈上的数值
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
            System.out.println("notification is " + notification.isSuccessful());
            pushManager.stopConnection();
        } catch (Exception e) {
            Log.error("Push Error.", e);
        }
    }
}
