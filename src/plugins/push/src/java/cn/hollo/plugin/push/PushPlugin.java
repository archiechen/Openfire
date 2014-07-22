package cn.hollo.plugin.push;

import java.io.File;

import org.jivesoftware.openfire.container.Plugin;
import org.jivesoftware.openfire.container.PluginManager;
import org.jivesoftware.openfire.interceptor.InterceptorManager;

public class PushPlugin implements Plugin {
	
	private PushInterceptor pushInterceptor = null;   

	@Override
	public void initializePlugin(PluginManager manager, File pluginDirectory) {
		pushInterceptor = new PushInterceptor();  
		InterceptorManager.getInstance().addInterceptor(pushInterceptor);  
	}

	@Override
	public void destroyPlugin() {
		if(pushInterceptor != null){  
			InterceptorManager.getInstance().removeInterceptor(pushInterceptor);  
		}  
	}

}
