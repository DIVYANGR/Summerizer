
package com.sri.csl.summarizer;
import java.io.*; 
import com.fasterxml.jackson.databind.MapperFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.command.InspectContainerResponse;
import com.github.dockerjava.api.model.ContainerNetwork;
import com.github.dockerjava.api.model.ExposedPort;
import com.github.dockerjava.api.model.NetworkSettings;
import com.github.dockerjava.api.model.Ports;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient;
import com.github.dockerjava.transport.DockerHttpClient;
import com.google.protobuf.InvalidProtocolBufferException;

import com.sri.containersec.message.ContainersecMessage.Container;
import com.sri.containersec.message.ContainersecMessage.ContainerInfo;
import com.sri.containersec.message.ContainersecMessage.ContainerNames;
import com.sri.containersec.message.ContainersecMessage.Event;
import com.sri.containersec.message.ContainersecMessage.FileDescriptor;
import com.sri.containersec.message.ContainersecMessage.Syscall;

import com.sri.containersec.message.ContainersecMessage.ContainerResources;
import com.sri.containersec.message.ContainersecMessage.ProcessActivity;
import com.sri.containersec.message.ContainersecMessage.FileActivity;
import com.sri.containersec.message.ContainersecMessage.NetworkActivity;
import com.sri.containersec.message.ContainersecMessage.ErrorActivity;
import com.sri.containersec.message.ContainersecMessage.PolicyAlerts;
import com.sri.containersec.message.ContainersecMessage.SummaryMessage;
import com.sri.containersec.message.ContainersecMessage.SummarizerMessage;
import com.sri.containersec.message.ContainersecMessage.SysdigMessage;
import com.sri.containersec.message.ContainersecMessage.SysdigMessageList;

import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.reflect.FieldUtils;
import org.apache.commons.lang.reflect.MethodUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.zeromq.SocketType;
import org.zeromq.ZContext;
import org.zeromq.ZMQ;

import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.UnknownHostException;
import java.util.*;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.stream.Collectors;

public class ReadFromForensics 
{ 
 
  File file = new File("C:\\Users\\Divyang\\Desktop\\Javacode\\test.txt"); 
  
  BufferedReader br = new BufferedReader(new FileReader(file)); 
  
  String st; 
  while ((st = br.readLine()) != null) 
    System.out.println(st); 
  
} 


public class SummarizerService {
    private static final Logger log = LoggerFactory.getLogger(SummarizerService.class);
    private static final Logger log1 = LoggerFactory.getLogger(SummarizerService.class);
    //private static final JsonFormat.Printer jsonPrinter = JsonFormat.printer();
    private final ReadFromForensics readfromforensics;
    private final LinkedBlockingQueue<byte[]> events;
    private final HashMap<String, ContainerResourceSummarizer> crsMap = new HashMap<>();
    private final DockerClient dockerClient;

    private ForensicsServer forensicsServer;

    /*
    private Map<String, InspectContainerResponse> inspectMap;
    private Map<String, Set<InetAddress>> addressMap;
    */

    public SummarizerService() {
        // Construct the events queue
        events = new LinkedBlockingQueue<>();

        // Get the docker client
        dockerClient = getDockerClient();

        /*
        // Get container inspect map
        inspectMap = getInspectMap();

        // Get the addresses of each container
        addressMap = getAddressMap();
        */

        // Start sysdig thread
        Thread sysdigThread = new Thread(() -> {
            // Connect to sysdig message queue
            try (ZContext context = new ZContext()) {
                ZMQ.Socket socket = context.createSocket(SocketType.SUB);
                String sysdigAddr = PropertiesService.getInstance().getProperty("sysdig.addr");
                log.info("Connecting to sysdig addr " + sysdigAddr);
                socket.connect(sysdigAddr);
                String sysdigTopic = PropertiesService.getInstance().getProperty("sysdig.topic");
                log.info("Subscribing to sysdig topic " + sysdigTopic);
                socket.subscribe(sysdigTopic.getBytes(ZMQ.CHARSET));
                log.info("Listening for events");
                while (true) {
                    // Read the topic
                    socket.recvStr();
                    // Read the event
                    byte[] event = socket.recv();
                    events.add(event);
                }
            }
        });
        sysdigThread.start();

        // Start summarizer thread
        Thread summarizerThread = new Thread(() -> {
            try (ZContext context = new ZContext()) {
                ZMQ.Socket socket = context.createSocket(SocketType.PUB);
                String summarizerAddr = PropertiesService.getInstance().getProperty("summarizer.addr");
                log.info("Binding to summarizer addr " + summarizerAddr);
                socket.bind(summarizerAddr);
                String summarizerTopic = PropertiesService.getInstance().getProperty("summarizer.topic");
                long timeQuantum = Long.parseLong(PropertiesService.getInstance().getProperty("time.quantum"));
                while (true) {
                    // Get start time
                    long start = System.currentTimeMillis();
                    log.info("Starting summary");
                    // Make a copy of the events
                    log.info("Making a copy of event list of size " + events.size());
                    List<byte[]> copy = new ArrayList<>(events.size());
                    events.drainTo(copy);
                    // Convert raw events into list of sysdig messages
                    List<SysdigMessage> sysdigMessages = getSysdigMessages(copy);
                    // Get a map of container id to sysdig messages
                    log.info("Getting map of container id to sysdig messages");
                    Map<String, List<SysdigMessage>> sysdigMap = getSysdigMap(sysdigMessages);
                    // Build the summary map for all containers
                    log.info("Building summary map for each container");
                    Map<String, SummaryMessage> summaries = new HashMap<>();
                    for (String containerId : sysdigMap.keySet()) {
                        List<SysdigMessage> sysdigMessages2 = sysdigMap.get(containerId);
                        SummaryMessage summaryMessage = getSummaryMessage(containerId, sysdigMessages2);
                        if (summaryMessage != null) {
                            summaries.put(containerId, summaryMessage);
                        }
                    }
                    // Build a map of container ids to names
                    Map<String, ContainerInfo> containerInfos = new HashMap<>();
                    List<com.github.dockerjava.api.model.Container> containerList = dockerClient.listContainersCmd().exec();
                    for (com.github.dockerjava.api.model.Container container : containerList) {
                        ContainerNames names = ContainerNames.newBuilder().addAllNames(Arrays.asList(container.getNames())).build();
                        ContainerInfo info = ContainerInfo.newBuilder()
                                .setCommand(container.getCommand())
                                .setCreated(container.getCreated())
                                .setId(container.getId())
                                .setImage(container.getImage())
                                .setImageId(container.getImageId())
                                .setNames(names)
                                .setStatus(container.getStatus())
                                .setState(container.getState())
                                .build();
                        containerInfos.put(container.getId().substring(0,12), info);
                    }
                    // Get the timestamp for this quantum
                    long timestamp = System.currentTimeMillis();
                    // Get the number of events for the time quantum
                    int eventCount = copy.size();
                    // Get the total byte size of events
                    int eventSize = 0;
                    for (byte[] event : copy) {
                        eventSize += event.length;
                    }
                    // Build the summarizer message
                    log.info("Building summarizerMessage for timestamp " + timestamp + " with " + eventCount + " events");
                    SummarizerMessage summarizerMessage = SummarizerMessage.newBuilder()
                            .setTimestamp(timestamp)
                            .putAllSummaries(summaries)
                            .putAllContainerInfo(containerInfos)
                            .setEventCount(eventCount)
                            .setEventSize(eventSize)
                            .build();
                    // Save the sysdig messages for this timestamp and each container_id in the forensics cache
                    for (String containerId : sysdigMap.keySet()) {
                        SysdigMessageList forensics = SysdigMessageList.newBuilder()
                                .addAllList(sysdigMap.get(containerId))
                                .build();
                        forensicsServer.addForensics(timestamp, containerId, GzipUtil.gzipCompress(forensics.toByteArray()));
                    }
                    // Debug the block write total bytes for each container
                    for (String container_id : summaries.keySet()) {
                        ContainerInfo info = containerInfos.get(container_id);
                        if (info == null) {
                            log.warn("No container info for container ID " + container_id + " (ignored)");
                            continue;
                        }
                        // Get first name if available
                        ContainerNames names = info.getNames();
                        String container_name = names.getNamesCount() > 0 ? names.getNames(0) : "unknown";
                        // Strip leading slash
                        container_name = StringUtils.stripStart(container_name, "/");
                        // Print summary stats
                        SummaryMessage summaryMessage = summaries.get(container_id);
                        printSummaryStats(container_id, container_name, summaryMessage);
                    }
                    // Send summarizer message
                    log.info("Sending topic and message");
                    socket.sendMore(summarizerTopic);
                    socket.send(summarizerMessage.toByteArray());
                    log.info("Done with summary");
                    // Get end time and calculate duration
                    long end = System.currentTimeMillis();
                    long duration = end - start;
                    // Sleep for the remainder of the time
                    try {
                        long remainder = (timeQuantum * 1000) - duration;
                        if (remainder > 0) {
                            Thread.sleep(remainder);
                        }
                    } catch (InterruptedException e) {
                        // Ignore
                    }
                }
            }
        });
        summarizerThread.start();

        // Start web server
        forensicsServer = ForensicsServer.getInstance();
        forensicsServer.start();
    }

    private void printSummaryStats(String container_id, String container_name, SummaryMessage summaryMessage) {
        log.info("container id/name: {}/{}", container_id, container_name);
        ContainerResources containerResources = summaryMessage.getContainerResources();
        float cpu = containerResources.getCpuUsagePct();
        long mem = containerResources.getMemUsageBytes();
        long block_read = containerResources.getBlockReadDeltaBytes();
        long block_write = containerResources.getBlockWriteDeltaBytes();
        long net_in = containerResources.getNetInputDeltaBytes();
        long net_out = containerResources.getNetOutputDeltaBytes();
        int proc_count = containerResources.getProcessCount();
        log.info("\tcpu: {}%, mem: {}, block read/write: {}/{}, net in/out: {}/{}, proc count: {}",
                cpu, mem, block_read, block_write, net_in, net_out, proc_count);
        ProcessActivity processActivity = summaryMessage.getProcessActivity();
        int exec = processActivity.getExecEvents();
        int kill = processActivity.getKillEvents();
        int fork = processActivity.getForkEvents();
        log.info("\tprocess exec: {}, kill: {}, fork: {}", exec, kill, fork);
        FileActivity fileActivity = summaryMessage.getFileActivity();
        int open = fileActivity.getOpenReadEvents();
        int delete = fileActivity.getDeleteEvents();
        int create = fileActivity.getCreateEvents();
        int chmod = fileActivity.getChmodEvents();
        int chown = fileActivity.getChownEvents();
        int mkdir = fileActivity.getDirectoryCreationEvents();
        log.info("\tfile open: {}, delete: {}, create: {}, chmod/chown: {}/{}, mkdir: {}",
                open, delete, create, chmod, chown, mkdir);
        NetworkActivity networkActivity = summaryMessage.getNetworkActivity();
        int in_connections = networkActivity.getInboundConnections();
        int out_connections = networkActivity.getInboundConnections();
        int listen_count = networkActivity.getListenPortCount();
        int in_ips = networkActivity.getInboundUniqueIp();
        int out_ips = networkActivity.getOutboundUniqueIp();
        int dns = networkActivity.getDnsQueryCount();
        long in_bytes = networkActivity.getInboundTcpByteCount();
        long out_bytes = networkActivity.getOutboundTcpByteCount();
        log.info("\tnetwork in/out connections: {}/{}, listen port: {}, in/out ips: {}/{}, dns: {}, in/out bytes: {}/{}",
                in_connections, out_connections, listen_count, in_ips, out_ips, dns, in_bytes, out_bytes);
    }

    private DockerClient getDockerClient() {
        DockerClientConfig config = DefaultDockerClientConfig.createDefaultConfigBuilder().build();
        acceptCaseInsensitiveEnums();
        DockerHttpClient httpClient = new ApacheDockerHttpClient.Builder()
                .dockerHost(config.getDockerHost())
                .sslConfig(config.getSSLConfig())
                .build();
        DockerClient dockerClient = DockerClientImpl.getInstance(config, httpClient);
        return dockerClient;
    }

    private void acceptCaseInsensitiveEnums() {
        try {
            Class<?> cls = Class.forName("com.github.dockerjava.core.DefaultObjectMapperHolder");
            Object instance = FieldUtils.readStaticField(cls, "INSTANCE");
            ObjectMapper objectMapper = (ObjectMapper) MethodUtils.invokeMethod(instance, "getObjectMapper", null);
            objectMapper.enable(MapperFeature.ACCEPT_CASE_INSENSITIVE_ENUMS);
        } catch (Exception e) {
            log.error("Failed to accept case insensitive enums");
        }
    }
    /*
    private Map<String, InspectContainerResponse> getInspectMap() {
        Map<String, InspectContainerResponse> map = new HashMap<>();

        // Get the ip addresses for each container
        List<com.github.dockerjava.api.model.Container> containers = dockerClient.listContainersCmd().exec();
        for (com.github.dockerjava.api.model.Container container : containers) {
            String containerId = container.getId();
            InspectContainerResponse response = dockerClient.inspectContainerCmd(containerId).exec();
            map.put(containerId, response);
        }

        return map;
    }

    private Map<String, Set<InetAddress>> getAddressMap() {
        Map<String, Set<InetAddress>> map = new HashMap<>();

        // Get the ip addresses for each container
        for (String containerId : inspectMap.keySet()) {
            InspectContainerResponse response = inspectMap.get(containerId);
            Set<InetAddress> set = new HashSet<>();
            NetworkSettings networkSettings = response.getNetworkSettings();
            Map<String, ContainerNetwork> networks =  networkSettings.getNetworks();
            for (String name : networks.keySet()) {
                ContainerNetwork network = networks.get(name);
                String ipAddress = network.getIpAddress();
                try {
                    InetAddress inetAddress = InetAddress.getByName(ipAddress);
                    set.add(inetAddress);
                } catch (UnknownHostException e) {
                    log.error("Failed to get address by name " + ipAddress);
                }
            }
            map.put(containerId, set);
        }

        return map;
    }
    */

    private ContainerResources getContainerResources(final String containerId) {
        ContainerResourceSummarizer summarizer = crsMap.computeIfAbsent(containerId,
                    id -> {
                        try {
                            return new ContainerResourceSummarizer(id);
                        } catch (Exception e) {
                            log.error("caught exception getting ContainerResourceSummarizer for container ID " + id, e);
                            return null;
                        }
                    });
        if (summarizer != null) {
            try {
                return summarizer.getSummary();
            } catch (Exception e) {
                log.error("caught exception generating resource summary for container ID " + containerId, e);
            }
        }
        // return empty summary on failure
        return ContainerResources.newBuilder().build();
    }

    private ProcessActivity getProcessActivity(List<SysdigMessage> sysdigMessages) {
        Map<String, Integer> syscalls = new HashMap<>();
        int activeProc = 0;
        int execEvents = 0;
        int killEvents = 0;
        int forkEvents = 0;
        int privEscalationEvents = 0;
        int exitEvents = 0;
        int unknownProc = 0;
        int coreDumpEvents = 0;
        int traceEvents = 0;
        int virtualizationEvents = 0;
        int unknownExecTargetEvents = 0;

        for (SysdigMessage sysdigMessage : sysdigMessages) {
            Event evt = sysdigMessage.getEvt();
            String category = evt.getCategory();
            String evtType = evt.getType();
            if (category.equals("process")) {
                // Increment the syscall count
                Syscall syscall = sysdigMessage.getSyscall();
                String syscallType = syscall.getType();
                syscalls.merge(syscallType, 1, Integer::sum);
                // TODO: activeProc
                // execEvents: execve/execve/execveat/execveat/kexec_file_load/kexec_load/kexec_load
                if (evtType.contains("exec")) {
                    execEvents++;
                }
                // killEvents: kill
                if (evtType.contains("kill")) {
                    killEvents++;
                }
                // forkEvents: fork/vfork
                if (evtType.contains("fork")) {
                    forkEvents++;
                }
                // privEscalationEvents: setpgid/setfsgid/setfsuid/setgid/setpgid/setregid/setresgid/setresuid/setreuid/setsid/setuid
                if (evtType.contains("set") && evtType.contains("id")) {
                    privEscalationEvents++;
                }
                // exitEvents: exit
                if (evtType.contains("exit")) {
                    exitEvents++;
                }
                // TODO: unknownProc
                // TODO: coreDumpEvents
                // traceEvents: ptrace
                if (evtType.contains("trace")) {
                    traceEvents++;
                }
                // virtualizationEvents: process_vm_readv/process_vm_readv/process_vm_writev/process_vm_writev
                if (evtType.contains("vm")) {
                    virtualizationEvents++;
                }
                // TODO: unknownExecTargetEvents
            }
        }

        return ProcessActivity.newBuilder()
                .putAllSyscalls(syscalls)
                .setActiveProc(activeProc)
                .setExecEvents(execEvents)
                .setKillEvents(killEvents)
                .setForkEvents(forkEvents)
                .setPrivEscalationEvents(privEscalationEvents)
                .setExitEvents(exitEvents)
                .setUnknownProc(unknownProc)
                .setCoreDumpEvents(coreDumpEvents)
                .setTraceEvents(traceEvents)
                .setVirtualizationEvents(virtualizationEvents)
                .setUnknownExecTargetEvents(unknownExecTargetEvents)
                .build();
    }

    private FileActivity getFileActivity(List<SysdigMessage> sysdigMessages) {
        Map<String, Integer> syscalls = new HashMap<>();
        int openReadEvents = 0;
        int openModifyEvents = 0;
        int deleteEvents = 0;
        int createEvents = 0;
        int chmodEvents = 0;
        int chownEvents = 0;
        int unknownProcessEvents = 0;
        int directoryCreationEvents = 0;
        int linkEvents = 0;
        int ioctlEvents = 0;
        int renameEvents = 0;
        int mountEvents = 0;
        int unmountEvents = 0;

        for (SysdigMessage sysdigMessage : sysdigMessages) {
            Event evt = sysdigMessage.getEvt();
            String category = evt.getCategory();
            String evtType = evt.getType();
            if (category.equals("file")) {
                // Increment the syscall count
                Syscall syscall = sysdigMessage.getSyscall();
                String syscallType = syscall.getType();
                syscalls.merge(syscallType, 1, Integer::sum);
                // openReadEvents: fsopen/open/openat
                if (evtType.contains("open")) {
                    openReadEvents++;
                }
                // TODO: openModifyEvents:
                // TODO: deleteEvents:
                // createEvents: creat/create_module
                if (evtType.contains("creat")) {
                    createEvents++;
                }
                // chmodEvents: chmod/fchmod/fchmodat
                if (evtType.contains("chmod")) {
                    chmodEvents++;
                }
                // chownEvents: chown/fchown/fchownat/lchown
                if (evtType.contains("chown")) {
                    chownEvents++;
                }
                // TODO: unknownProcessEvents:
                // directoryCreationEvents: mkdir/mkdirat
                if (evtType.contains("mkdir")) {
                    directoryCreationEvents++;
                }
                // linkEvents: link/linkat/symlink/smylinkat/unlink/unlinkat
                if (evtType.contains("link")) {
                    linkEvents++;
                }
                // ioctlEvents: ioctl
                if (evtType.contains("ioctl")) {
                    ioctlEvents++;
                }
                // renameEvents: rename/renameat/renameat2
                if (evtType.contains("rename")) {
                    renameEvents++;
                }
                // mountEvents: fsmount/mount/move_mount
                if (evtType.contains("mount") && !evtType.contains("umount")) {
                    mountEvents++;
                }
                // unmountEvents: umount/umount2
                if (evtType.contains("umount")) {
                    unmountEvents++;
                }
            }
        }

        return FileActivity.newBuilder()
                .putAllSyscalls(syscalls)
                .setOpenReadEvents(openReadEvents)
                .setOpenModifyEvents(openModifyEvents)
                .setDeleteEvents(deleteEvents)
                .setCreateEvents(createEvents)
                .setChmodEvents(chmodEvents)
                .setChownEvents(chownEvents)
                .setUnknownProcessEvents(unknownProcessEvents)
                .setDirectoryCreationEvents(directoryCreationEvents)
                .setLinkEvents(linkEvents)
                .setIoctlEvents(ioctlEvents)
                .setRenameEvents(renameEvents)
                .setMountEvents(mountEvents)
                .setUnmountEvents(unmountEvents)
                .build();
    }

    private InetAddress getInetAddressByName(String host) {
        InetAddress address = null;
        if (host != null && !host.isEmpty()) {
            try {
                address = InetAddress.getByName(host);
            } catch (UnknownHostException e) {
                log.warn("Unknown host " + host);
            }
        }
        return address;
    }

    private NetworkActivity getNetworkActivity(String containerId, InspectContainerResponse containerInfo, List<SysdigMessage> sysdigMessages) {
        Map<String, Integer> syscalls = new HashMap<>();
        int inboundConnections = 0; // Have data
        int outboundConnections = 0;  // Have data
        int listenPortCount = 0;  // Have data
        int inboundUniqueIp = 0; // Have data
        int outboundUniqueIp = 0; // Have data
        int inboundUdpCount = 0;  // Have data
        int outboundUdpCount = 0; // Have data
        int inboundTcpFlowCount = 0;
        int outboundTcpFlowCount = 0;
        int dnsQueryCount = 0;          // Have data
        long inboundTcpByteCount = 0;   // Have data
        long outboundTcpByteCount = 0;  // Have data

        // Listen port count
        NetworkSettings networkSettings = containerInfo.getNetworkSettings();
        Ports ports = networkSettings.getPorts();
        Map<ExposedPort, Ports.Binding[]> bindings = ports.getBindings();
        Set<ExposedPort> exposedPorts = bindings.keySet();
        listenPortCount = exposedPorts.size();

        // Unique set of inbound/outbound IP addresses
        Set<InetAddress> inboundIps = new HashSet<>();
        Set<InetAddress> outboundIps = new HashSet<>();

        // Get the set of IP addresses for the container
        Set<InetAddress> containerIps = new HashSet<>();
        Map<String, ContainerNetwork> networks =  networkSettings.getNetworks();
        for (String name : networks.keySet()) {
            try {
                if (name.equals("host")) {
                    // Special handling for the host
                    Enumeration<NetworkInterface> networkInterfaces = NetworkInterface.getNetworkInterfaces();
                    for (NetworkInterface networkInterface : Collections.list(networkInterfaces)) {
                        Enumeration<InetAddress> inetAddresses = networkInterface.getInetAddresses();
                        containerIps.addAll(Collections.list(inetAddresses));
                    }
                } else {
                    // Get container ips from container info
                    ContainerNetwork network = networks.get(name);
                    String ipAddress = network.getIpAddress();
                    InetAddress inetAddress = InetAddress.getByName(ipAddress);
                    containerIps.add(inetAddress);
                }
            } catch (Exception e) {
                log.warn("Failed to get to get container IPs for containerId = " + containerId, e);
            }
        }

        for (SysdigMessage sysdigMessage : sysdigMessages) {
            // Get event fields
            Event evt = sysdigMessage.getEvt();
            boolean isIo = evt.getIsIo();
            String evtType = evt.getType();
            String category = evt.getCategory();
            // Get file descriptor fields
            FileDescriptor fd = sysdigMessage.getFd();
            String fdType = fd.getType();
            String l4proto = fd.getL4Proto();
            int sport = fd.getSport();
            String localIp = fd.getLip();
            String remoteIp = fd.getRip();
            int rawargRes = evt.getRawargRes();

            if (category.equals("net")) {
                // Inbound/Outbound connections
                if (evtType.startsWith("accept")) {
                    inboundConnections++;
                } else if (evtType.equals("connect")) {
                    outboundConnections++;
                }

                // DNS query count (assume all UDP connects to server port 53 are DNS)
                if (sport == 53 && evtType.equals("connect") && l4proto.equals("udp")) {
                    dnsQueryCount++;
                }

                // Inbound/Outbound TCP byte count (see iobytes_net.lua)
                if (isIo && (fdType.equals("ipv4") || fdType.equals("ipv6")) && l4proto.equals("tcp")) {
                    boolean isIoRead = evt.getIsIoRead();
                    if (isIoRead) {
                        inboundTcpByteCount += rawargRes;
                    } else {
                        outboundTcpByteCount += rawargRes;
                    }
                }

                // Get the local/remote inet addresses
                InetAddress localAddr = getInetAddressByName(localIp);
                InetAddress remoteAddr = getInetAddressByName(remoteIp);
                if (localAddr == null || remoteAddr == null) {
                    continue;
                }

                // Inbound/Outbound unique IP count
                if (evtType.startsWith("accept")) {
                    inboundIps.add(localAddr);
                } else if (evtType.equals("connect")) {
                    outboundIps.add(remoteAddr);
                }

                // Inbound/Outbound TCP/UDP counts
                if (evtType.equals("connect")) {
                    if (l4proto.equals("udp")) {
                        if (!containerIps.contains(localAddr)) {
                            inboundUdpCount++;
                        } else {
                            outboundUdpCount++;
                        }
                    } else if (l4proto.equals("tcp")) {
                        if (!containerIps.contains(localAddr)) {
                            inboundTcpFlowCount++;
                        } else {
                            outboundTcpFlowCount++;
                        }
                    }
                }
            }
        }

        // Inbound/Outbound unique IP count
        inboundUniqueIp = inboundIps.size();
        outboundUniqueIp = outboundIps.size();

        return NetworkActivity.newBuilder()
                .putAllSyscalls(syscalls)
                .setInboundConnections(inboundConnections)
                .setOutboundConnections(outboundConnections)
                .setListenPortCount(listenPortCount)
                .setInboundUniqueIp(inboundUniqueIp)
                .setOutboundUniqueIp(outboundUniqueIp)
                .setInboundUdpCount(inboundUdpCount)
                .setOutboundUdpCount(outboundUdpCount)
                .setInboundTcpFlowCount(inboundTcpFlowCount)
                .setOutboundTcpFlowCount(outboundTcpFlowCount)
                .setDnsQueryCount(dnsQueryCount)
                .setInboundTcpByteCount(inboundTcpByteCount)
                .setOutboundTcpByteCount(outboundTcpByteCount)
                .build();
    }

    // TODO
    private ErrorActivity getErrorActivity() {
        return ErrorActivity.newBuilder().build();
    }

    // TODO
    private PolicyAlerts getPolicyAlerts() {
        return PolicyAlerts.newBuilder().build();
    }

    /**
     * Get a summary message for a list of sysdig messages
     *
     * @param sysdigMessages The list of sysdig messages for a given container
     * @return a summary message for those events
     */
    private SummaryMessage getSummaryMessage(final String containerId, List<SysdigMessage> sysdigMessages) {
        // Inspect the container
        InspectContainerResponse containerInfo = null;
        try {
            // Catch any exceptions and ignore
            containerInfo = dockerClient.inspectContainerCmd(containerId).exec();
        } catch (Exception e) {
        }
        if (containerInfo != null) {
            // Build summary message if we have valid container info
            SummaryMessage summaryMessage = SummaryMessage.newBuilder()
                    .setContainerResources(getContainerResources(containerId))
                    .setProcessActivity(getProcessActivity(sysdigMessages))
                    .setFileActivity(getFileActivity(sysdigMessages))
                    .setNetworkActivity(getNetworkActivity(containerId, containerInfo, sysdigMessages))
                    .setErrorActivity(getErrorActivity())
                    .setPolicyAlerts(getPolicyAlerts())
                    .build();
            return summaryMessage;
        } else {
            // Return null if we do not have valid container info
            return null;
        }
    }

    public List<SysdigMessage> getSysdigMessages(List<byte[]> events) {
        List<SysdigMessage> sysdigMessages = new ArrayList<>();
        for (byte[] event : events) {
            try {
                // Parse the sysdig message
                SysdigMessage sysdigMessage = SysdigMessage.parseFrom(event);
                // Put message in the list
                sysdigMessages.add(sysdigMessage);
            } catch (InvalidProtocolBufferException e) {
                log.error("Failed to parse event", e);
            }
        }

        return sysdigMessages;
    }

    /**
     * Convert list of messages into map of container id to sub-list of messages
     *
     * @param sysdigMessages The sysdig message list
     * @return a map of container id to sysdig message list
     */
    private Map<String, List<SysdigMessage>> getSysdigMap(List<SysdigMessage> sysdigMessages) {
        Map<String, List<SysdigMessage>> sysdigMap = new HashMap<>();

        // Process the events in the copy
        for (SysdigMessage sysdigMessage : sysdigMessages) {
            // Get the sub messages
            Container container = sysdigMessage.getContainer();
            String containerId = container.getId();
            // Ignore invalid containerIds
            if (containerId == null || containerId.isEmpty()) {
                continue;
            }
            // Add the message to the map
            sysdigMap.putIfAbsent(containerId, new ArrayList<>());
            List<SysdigMessage> list = sysdigMap.get(containerId);
            list.add(sysdigMessage);
        }

        return sysdigMap;
    }

    public static void main(String[] args) {
        new SummarizerService();
    }
}
