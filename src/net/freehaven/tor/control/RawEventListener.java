
package net.freehaven.tor.control;

/**
 * Receive the raw event data.
 * <p>
 * This file is auto-generated by {@code generate-TorControlCommands.py}
 *
 * @see <a href="https://torproject.gitlab.io/torspec/control-spec/#asynchronous-events">Control Port Asynchronous events</a>
 */
public interface RawEventListener {
    /**
     * Receive the raw event data from these events:
     * <ul>
     * <li>{@link TorControlCommands#EVENT_CIRCUIT_STATUS}</li>
     * <li>{@link TorControlCommands#EVENT_CIRCUIT_STATUS_MINOR}</li>
     * <li>{@link TorControlCommands#EVENT_STREAM_STATUS}</li>
     * <li>{@link TorControlCommands#EVENT_OR_CONN_STATUS}</li>
     * <li>{@link TorControlCommands#EVENT_BANDWIDTH_USED}</li>
     * <li>{@link TorControlCommands#EVENT_DEBUG_MSG}</li>
     * <li>{@link TorControlCommands#EVENT_INFO_MSG}</li>
     * <li>{@link TorControlCommands#EVENT_NOTICE_MSG}</li>
     * <li>{@link TorControlCommands#EVENT_WARN_MSG}</li>
     * <li>{@link TorControlCommands#EVENT_ERR_MSG}</li>
     * <li>{@link TorControlCommands#EVENT_NEW_DESC}</li>
     * <li>{@link TorControlCommands#EVENT_ADDRMAP}</li>
     * <li>{@link TorControlCommands#EVENT_DESCCHANGED}</li>
     * <li>{@link TorControlCommands#EVENT_NS}</li>
     * <li>{@link TorControlCommands#EVENT_STATUS_GENERAL}</li>
     * <li>{@link TorControlCommands#EVENT_STATUS_CLIENT}</li>
     * <li>{@link TorControlCommands#EVENT_STATUS_SERVER}</li>
     * <li>{@link TorControlCommands#EVENT_GUARD}</li>
     * <li>{@link TorControlCommands#EVENT_STREAM_BANDWIDTH_USED}</li>
     * <li>{@link TorControlCommands#EVENT_CLIENTS_SEEN}</li>
     * <li>{@link TorControlCommands#EVENT_BUILDTIMEOUT_SET}</li>
     * <li>{@link TorControlCommands#EVENT_GOT_SIGNAL}</li>
     * <li>{@link TorControlCommands#EVENT_CONF_CHANGED}</li>
     * <li>{@link TorControlCommands#EVENT_CONN_BW}</li>
     * <li>{@link TorControlCommands#EVENT_CELL_STATS}</li>
     * <li>{@link TorControlCommands#EVENT_CIRC_BANDWIDTH_USED}</li>
     * <li>{@link TorControlCommands#EVENT_TRANSPORT_LAUNCHED}</li>
     * <li>{@link TorControlCommands#EVENT_HS_DESC}</li>
     * <li>{@link TorControlCommands#EVENT_NETWORK_LIVENESS}</li>
     * </ul>
     *
     * @see <a href="https://torproject.gitlab.io/torspec/control-spec/#asynchronous-events">Control Port Asynchronous events</a>
     */
    public void onEvent(String keyword, String data);
}