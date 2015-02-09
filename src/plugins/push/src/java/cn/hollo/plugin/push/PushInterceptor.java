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
import org.dom4j.Element;
import org.jivesoftware.database.DbConnectionManager;
import org.jivesoftware.openfire.PresenceManager;
import org.jivesoftware.openfire.XMPPServer;
import org.jivesoftware.openfire.interceptor.InterceptorManager;
import org.jivesoftware.openfire.interceptor.PacketInterceptor;
import org.jivesoftware.openfire.interceptor.PacketRejectedException;
import org.jivesoftware.openfire.muc.*;
import org.jivesoftware.openfire.privacy.PrivacyList;
import org.jivesoftware.openfire.privacy.PrivacyListManager;
import org.jivesoftware.openfire.session.Session;
import org.jivesoftware.openfire.user.UserManager;
import org.jivesoftware.openfire.user.UserNotFoundException;
import org.jivesoftware.util.JiveGlobals;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xmpp.packet.*;
import redis.clients.jedis.Jedis;
import redis.clients.jedis.JedisPool;
import redis.clients.jedis.JedisPoolConfig;

/**
 * <b>function:</b> send offline msg plugin
 *
 * @author MZH
 */
public class PushInterceptor implements PacketInterceptor {
	private static final Logger Log = LoggerFactory
			.getLogger(PushInterceptor.class);
	// Hook for intercpetorn
	final private InterceptorManager interceptorManager;
	final private UserManager userManager;
    final private PresenceManager presenceManager;
    final private MultiUserChatService mucService;
    final private HashMap<String,AtomicInteger> offlineCounter;
    final JedisPoolConfig poolConfig;
    final JedisPool jedisPool;
    final PrivacyListManager privacyListManager;
    final private String pushChannel;

    public PushInterceptor() {
		interceptorManager = InterceptorManager.getInstance();
		interceptorManager.addInterceptor(this);

		XMPPServer server = XMPPServer.getInstance();
		userManager = server.getUserManager();
		presenceManager = server.getPresenceManager();
        privacyListManager = PrivacyListManager.getInstance();
        offlineCounter = new HashMap<String, AtomicInteger>();
        mucService = XMPPServer.getInstance()
                .getMultiUserChatManager()
                .getMultiUserChatService("conference");
        String jedisHost = JiveGlobals.getProperty("redis.host", "localhost");
        int jedisPort = JiveGlobals.getIntProperty("redis.port",6379);
        poolConfig = new JedisPoolConfig();
        jedisPool = new JedisPool(poolConfig, jedisHost, jedisPort, 100);
        pushChannel =JiveGlobals.getProperty("redis.push","hollo_apns");
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

            if (p.getType()== Presence.Type.unavailable) {
                offlineCounter.remove(p.getFrom().getNode());
            }
        }
    }

	/**
	 * <b>send offline msg from this function </b>
	 */
	private void doAction(Packet packet, boolean incoming, boolean processed,
			Session session) throws PacketRejectedException {
		Message message = (Message) packet;
		Log.info("is group? " + (message.getType() == Message.Type.groupchat));
		if (message.getType() == Message.Type.chat) {
			JID recipient = message.getTo();
			// get message
			try {
                PrivacyList privacyList =  privacyListManager.getPrivacyList(message.getTo().getNode(), "banlist");
                boolean shouldBlock = privacyList.shouldBlockPacket(message);
                if(shouldBlock){
                    Log.info("Should block packet. reason "+privacyList.asElement().asXML());
                    throw new PacketRejectedException();
                }
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
                    JSONObject jo = getJsonObject(message, recipient, deviceToken);
                    jo.put("type","chat");
                    pns(jo.toString());
				}else{
                    offlineCounter.remove(recipient.getNode());
                }// end if

			} catch (UserNotFoundException e) {
				Log.warn("Push Error.", e);
			} catch (JSONException e) {
                Log.warn("Create json error for member." + recipient.getNode(), e);
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
                            JSONObject jo = getJsonObject(message, member, deviceToken);
                            jo.put("room_id",recipient.getNode());
                            jo.put("type","groupchat");
                            Log.info("Message json is " + jo.toString());
                            pns(jo.toString());
                        }
					}else{
                        offlineCounter.remove(member.getNode());
                    }// end if
				} catch (UserNotFoundException e) {
					Log.warn("User not found.", e);
				} catch (JSONException e) {
                    Log.warn("Create json error for member." + member.getNode(), e);
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
                            JSONObject jo = getJsonObject(message, owner, deviceToken);
                            jo.put("room_id",recipient.getNode());
                            jo.put("type","groupchat");
                            Log.info("Message json is " + jo.toString());
                            pns(jo.toString());
                        }
					}else{
                        offlineCounter.remove(owner.getNode());
                    }// end if

				} catch (UserNotFoundException e) {
					Log.warn("User not found "+owner.getNode(), e);
				} catch (JSONException e) {
                    Log.warn("Create json error for owner."+owner.getNode(), e);
                }
            }
		}
	}

    private JSONObject getJsonObject(Message message, JID recipient, String deviceToken) throws JSONException {
        Element params =message.getChildElement("params","http://hollo.cn/xmpp/message/params");
        JSONObject jo = new JSONObject();
        jo.put("nickname", params.elementText("nickname"))
            .put("messageType", params.elementText("messageType"))
            .put("body", message.getBody())
                .put("to", recipient.getNode()).put("token", deviceToken).put("badge",offlineCounter.get(recipient.getNode()).get());
        return jo;
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

	public void pns(String message) {
        Jedis jedis = jedisPool.getResource();
        Long published = jedis.publish(pushChannel, message);
        Log.info("APNS published "+published);
        jedisPool.returnResource(jedis);

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
