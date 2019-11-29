
package net.freehaven.tor.control;

/**
 * Receive the events from Tor.
 * <p>
 * This file is auto-generated by {@code generate-TorControlCommands.py}
 *
 * @see <a href="https://torproject.gitlab.io/torspec/control-spec/#asynchronous-events">Control Port Asynchronous events</a>
 */
public abstract class EventListener implements RawEventListener {
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
     * <li>{@link TorControlCommands#EVENT_NEWCONSENSUS}</li>
     * <li>{@link TorControlCommands#EVENT_BUILDTIMEOUT_SET}</li>
     * <li>{@link TorControlCommands#EVENT_GOT_SIGNAL}</li>
     * <li>{@link TorControlCommands#EVENT_CONF_CHANGED}</li>
     * <li>{@link TorControlCommands#EVENT_CONN_BW}</li>
     * <li>{@link TorControlCommands#EVENT_CELL_STATS}</li>
     * <li>{@link TorControlCommands#EVENT_CIRC_BANDWIDTH_USED}</li>
     * <li>{@link TorControlCommands#EVENT_TRANSPORT_LAUNCHED}</li>
     * <li>{@link TorControlCommands#EVENT_HS_DESC}</li>
     * <li>{@link TorControlCommands#EVENT_HS_DESC_CONTENT}</li>
     * <li>{@link TorControlCommands#EVENT_NETWORK_LIVENESS}</li>
     * </ul>
     *
     * @see <a href="https://torproject.gitlab.io/torspec/control-spec/#asynchronous-events">Control Port Asynchronous events</a>
     */
    public void onEvent(String keyword, String data) {
        switch(keyword) {
            case TorControlCommands.EVENT_CIRCUIT_STATUS:
                circuitStatus(data);
                break;
            case TorControlCommands.EVENT_CIRCUIT_STATUS_MINOR:
                circuitStatusMinor(data);
                break;
            case TorControlCommands.EVENT_STREAM_STATUS:
                streamStatus(data);
                break;
            case TorControlCommands.EVENT_OR_CONN_STATUS:
                orConnStatus(data);
                break;
            case TorControlCommands.EVENT_BANDWIDTH_USED:
                bandwidthUsed(data);
                break;
            case TorControlCommands.EVENT_DEBUG_MSG:
                debugMsg(data);
                break;
            case TorControlCommands.EVENT_INFO_MSG:
                infoMsg(data);
                break;
            case TorControlCommands.EVENT_NOTICE_MSG:
                noticeMsg(data);
                break;
            case TorControlCommands.EVENT_WARN_MSG:
                warnMsg(data);
                break;
            case TorControlCommands.EVENT_ERR_MSG:
                errMsg(data);
                break;
            case TorControlCommands.EVENT_NEW_DESC:
                newDesc(data);
                break;
            case TorControlCommands.EVENT_ADDRMAP:
                addrMap(data);
                break;
            case TorControlCommands.EVENT_DESCCHANGED:
                descChanged(data);
                break;
            case TorControlCommands.EVENT_NS:
                ns(data);
                break;
            case TorControlCommands.EVENT_STATUS_GENERAL:
                statusGeneral(data);
                break;
            case TorControlCommands.EVENT_STATUS_CLIENT:
                statusClient(data);
                break;
            case TorControlCommands.EVENT_STATUS_SERVER:
                statusServer(data);
                break;
            case TorControlCommands.EVENT_GUARD:
                guard(data);
                break;
            case TorControlCommands.EVENT_STREAM_BANDWIDTH_USED:
                streamBandwidthUsed(data);
                break;
            case TorControlCommands.EVENT_CLIENTS_SEEN:
                clientsSeen(data);
                break;
            case TorControlCommands.EVENT_NEWCONSENSUS:
                newConsensus(data);
                break;
            case TorControlCommands.EVENT_BUILDTIMEOUT_SET:
                buildTimeoutSet(data);
                break;
            case TorControlCommands.EVENT_GOT_SIGNAL:
                gotSignal(data);
                break;
            case TorControlCommands.EVENT_CONF_CHANGED:
                confChanged(data);
                break;
            case TorControlCommands.EVENT_CONN_BW:
                connBw(data);
                break;
            case TorControlCommands.EVENT_CELL_STATS:
                cellStats(data);
                break;
            case TorControlCommands.EVENT_CIRC_BANDWIDTH_USED:
                circBandwidthUsed(data);
                break;
            case TorControlCommands.EVENT_TRANSPORT_LAUNCHED:
                transportLaunched(data);
                break;
            case TorControlCommands.EVENT_HS_DESC:
                hsDesc(data);
                break;
            case TorControlCommands.EVENT_HS_DESC_CONTENT:
                hsDescContent(data);
                break;
            case TorControlCommands.EVENT_NETWORK_LIVENESS:
                networkLiveness(data);
                break;
            default:
                unrecognized(data);
        }
    }

    public abstract void circuitStatus(String data);

    public abstract void circuitStatusMinor(String data);

    public abstract void streamStatus(String data);

    public abstract void orConnStatus(String data);

    public abstract void bandwidthUsed(String data);

    public abstract void debugMsg(String data);

    public abstract void infoMsg(String data);

    public abstract void noticeMsg(String data);

    public abstract void warnMsg(String data);

    public abstract void errMsg(String data);

    public abstract void newDesc(String data);

    public abstract void addrMap(String data);

    public abstract void descChanged(String data);

    public abstract void ns(String data);

    public abstract void statusGeneral(String data);

    public abstract void statusClient(String data);

    public abstract void statusServer(String data);

    public abstract void guard(String data);

    public abstract void streamBandwidthUsed(String data);

    public abstract void clientsSeen(String data);

    public abstract void newConsensus(String data);

    public abstract void buildTimeoutSet(String data);

    public abstract void gotSignal(String data);

    public abstract void confChanged(String data);

    public abstract void connBw(String data);

    public abstract void cellStats(String data);

    public abstract void circBandwidthUsed(String data);

    public abstract void transportLaunched(String data);

    public abstract void hsDesc(String data);

    public abstract void hsDescContent(String data);

    public abstract void networkLiveness(String data);

    public abstract void unrecognized(String data);

}