
/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Wires a global mouse listener to listen for side mouse button clicks to trigger navigation
//@category Experimental

import java.awt.AWTEvent;
import java.awt.Toolkit;
import java.awt.event.AWTEventListener;
import java.awt.event.MouseEvent;
import java.util.Set;

import docking.ActionContext;
import docking.action.DockingActionIf;
import ghidra.app.script.GhidraScript;
import ghidra.framework.plugintool.PluginTool;
import ghidra.util.Swing;

public class MouseToAndFroScript extends GhidraScript {

	private static final String ACTION_OWNER = "NextPrevAddressPlugin";
	private static AWTEventListener LISTENER;

	@Override
	protected void run() throws Exception {

		if (isRunningHeadless()) {
			return;
		}

		createListener();

		Toolkit tk = Toolkit.getDefaultToolkit();

		// don't repeatedly add the listener 
		tk.removeAWTEventListener(LISTENER);
		tk.addAWTEventListener(LISTENER, AWTEvent.MOUSE_EVENT_MASK);
	}

	private void createListener() {

		if (LISTENER != null) {
			return;
		}

		LISTENER = e -> {
			MouseEvent mousey = (MouseEvent) e;

			int id = mousey.getID();
			if (id != MouseEvent.MOUSE_CLICKED) {
				return; // only handle one time (ignore pressed/released)
			}

			// assume button 4 is left-side button; button 5 is right-side button
			int button = mousey.getButton();
			if (button == 4) {
				DockingActionIf back = getNavigationAction("Previous in History Buffer");
				Swing.runLater(() -> {
					back.actionPerformed(new ActionContext());
				});
			}
			else if (button == 5) {
				DockingActionIf forward = getNavigationAction("Next in History Buffer");
				Swing.runLater(() -> {
					forward.actionPerformed(new ActionContext());
				});
			}
		};
	}

	private DockingActionIf getNavigationAction(String name) {
		PluginTool tool = state.getTool();
		Set<DockingActionIf> actions = tool.getDockingActionsByOwnerName(ACTION_OWNER);
		for (DockingActionIf action : actions) {
			if (action.getName().equals(name)) {
				return action;
			}
		}
		return null;
	}
}
