###############################################################################
# OpenVAS Vulnerability Test
# $Id: ping_host.nasl 10223 2018-06-15 14:26:20Z cfischer $
#
# Ping Host
#
# Authors:
# Michael Meyer
#
# Copyright:
# Copyright (c) 2009, 2014 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100315");
  script_version("$Revision: 10223 $");
  script_tag(name:"last_modification", value:"$Date: 2018-06-15 16:26:20 +0200 (Fri, 15 Jun 2018) $");
  script_tag(name:"creation_date", value:"2009-10-26 10:02:32 +0100 (Mon, 26 Oct 2009)");
  script_tag(name:"cvss_base", value:"0.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_name("Ping Host");
  script_category(ACT_SCANNER);
  script_family("Port scanners");
  script_copyright("This script is Copyright (C) 2009, 2014, 2016 Greenbone Networks GmbH");

  script_add_preference(name:"Use nmap", type:"checkbox", value:"yes");

  ### In the following two lines, unreachable is spelled incorectly.
  ### Unfortunately, this must stay in order to keep compatibility with existing scan configs.
  script_add_preference(name:"Report about unrechable Hosts", type:"checkbox", value:"no");
  script_add_preference(name:"Mark unrechable Hosts as dead (not scanning)", type:"checkbox", value:"no");
  script_add_preference(name:"Report about reachable Hosts", type:"checkbox", value:"no");
  script_add_preference(name:"Use ARP", type:"checkbox", value:"no");
  script_add_preference(name:"Do a TCP ping", type:"checkbox", value:"no");
  script_add_preference(name:"TCP ping tries also TCP-SYN ping", type:"checkbox", value:"no");
  script_add_preference(name:"TCP ping tries only TCP-SYN ping", type:"checkbox", value:"no");
  script_add_preference(name:"Do an ICMP ping", type:"checkbox", value:"yes");
  script_add_preference(name:"nmap additional ports for -PA", type:"entry", value:"137,587,3128,8081");
  script_add_preference(name:"nmap: try also with only -sP", type:"checkbox", value:"no");
  script_add_preference(name:"Log nmap output", type:"checkbox", value:"no");

  script_tag(name:"summary", value:"This check tries to determine whether a remote host is up (alive).

  Several methods are used for this depending on configuration of this check.");

  script_tag(name:"insight", value:"Whether a host is up can be detected in 3 different ways:

  - A ICMP message is sent to the host and a response is taken as alive sign.

  - An ARP request is sent and a response is taken as alive sign.

  - A number of typical TCP services (namely the 20 top ports of nmap)
  are tried and their presence is taken as alive sign.

  None of the methods is failsafe. It depends on network and/or host configurations
  whether they succeed or not. Both, false positives and false negatives can occur.
  Therefore the methods are configurable.

  If you select to not mark unreachable hosts as dead, no alive detections are
  executed and the host is assumed to be available for scanning.

  In case it is configured that hosts are never marked as dead, this can cause
  considerable timeouts and therefore a long scan duration in case the hosts
  are in fact not available.

  The available methods might fail for the following reasons:

  - ICMP: This might be disabled for a environment and would then cause false
  negatives as hosts are believed to be dead that actually are alive. In constrast
  it is also possible that a Firewall between the scanner and the target host is answering
  to the ICMP message and thus hosts are believed to be alive that actually are dead.

  - TCP ping: Similar to the ICMP case a Firewall between the scanner and the target might
  answer to the sent probes and thus hosts are believed to be alive that actually are dead.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("misc_func.inc");
include("host_details.inc");
include("network_func.inc");

function check_pa_port_list( list ) {

  local_var list, ports, port;

  if( ! list ) return FALSE;

  ports = split( list, sep:",", keep:FALSE );

  foreach port( ports ) {
    if( ! ereg( pattern:"^[0-9]{1,5}$", string:port ) ) {
      return FALSE;
    }
    if( int( port ) > 65535 ) return FALSE;
  }
  return TRUE;
}

function run_tcp_syn_ping( argv, pa_ports, ip, pattern, report_up, log_output ) {

  local_var argv, pa_ports, ip, pattern, report_up, log_output;
  local_var argv_tcp_syn, res, report;

  argv_tcp_syn = argv;
  argv_tcp_syn[x++] = '-PS' + pa_ports;
  argv_tcp_syn[x++] = ip;

  res = pread( cmd:"nmap", argv:argv_tcp_syn );

  if( res && egrep( pattern:pattern, string:res ) && "Host seems down" >!< res ) {
    if( "yes" >< report_up || "yes" >< log_output ) {
      report = "";
      if( "yes" >< report_up )
        report += 'Host is up (successful TCP SYN service ping), Method: nmap\n';
      if( "yes" >< log_output )
        report += 'nmap command: ' + join( list:argv_tcp_syn ) + '\n' + res;
      log_message( port:0, data:report );
    }
    set_kb_item( name:"/tmp/ping/TCP", value:1 );
    exit( 0 );
  }
}

use_nmap          = script_get_preference("Use nmap");
report_up         = script_get_preference("Report about reachable Hosts");
### In the following two lines, unreachable is spelled incorectly.
### Unfortunately, this must stay in order to keep compatibility with existing scan configs.
report_dead       = script_get_preference("Report about unrechable Hosts");
mark_dead         = script_get_preference("Mark unrechable Hosts as dead (not scanning)");
icmp_ping         = script_get_preference("Do an ICMP ping");
tcp_ping          = script_get_preference("Do a TCP ping");
tcp_syn_ping      = script_get_preference("TCP ping tries also TCP-SYN ping");
tcp_syn_ping_only = script_get_preference("TCP ping tries only TCP-SYN ping");
arp_ping          = script_get_preference("Use ARP");
sp_only           = script_get_preference("nmap: try also with only -sP");
log_output        = script_get_preference("Log nmap output");

set_kb_item( name:"/ping_host/mark_dead", value:mark_dead );
set_kb_item( name:"/tmp/start_time", value:unixtime() );

if( islocalhost() ) exit( 0 );

if( "no" >< icmp_ping && "no" >< tcp_ping && "no" >< arp_ping && "no" >< sp_only ) {
  log_message( data:"The alive test was not launched because no method was selected." );
  exit( 0 );
}

if( "no" >< mark_dead && "no" >< report_dead ) {
  if( "yes" >< log_output )
    log_message( data:"'Log nmap output' was set to 'yes' but 'Report about unrechable Hosts' and 'Mark unrechable Hosts as dead (not scanning)' to no. Plugin will exit without logging." );
  exit( 0 );
}

if( "yes" >< use_nmap && ! find_in_path( 'nmap' ) ) {
  log_message( data:'Nmap was selected for host discovery but is not present on this system.\nFalling back to built-in discovery method.' );
  use_nmap = "no";
}

if( "yes" >< use_nmap ) {

  argv[x++] = 'nmap';
  argv[x++] = '--reason';
  argv[x++] = '-sP';

  if( "yes" >!< arp_ping )
    argv[x++] = "--send-ip";

  ip = get_host_ip();

  pattern = "Host.*(is|appears to be) up";

  if( TARGET_IS_IPV6() ) {
    argv[x++] = "-6";
  }

  if( "yes" >< sp_only ) {

    argv_sp_only = argv;
    argv_sp_only[x++] = ip;

    res = pread( cmd:"nmap", argv:argv_sp_only );

    if( res && egrep( pattern:pattern, string:res ) && "Host seems down" >!< res ) {
      if( "yes" >< report_up || "yes" >< log_output ) {
        report = "";
        if( "received arp-response" >< res )
          reason = 'ARP';
        else
          reason = 'ICMP';

        if( "yes" >< report_up )
          report += 'Host is up (successful ' + reason + ' ping), Method: nmap\n';
        if( "yes" >< log_output )
          report += 'nmap command: ' + join( list:argv_sp_only ) + '\n' + res;
        log_message( data:report, port:0 );
      }
      # TBD: This is mostly wrong / unreliable as an -sP "consists of an ICMP echo request, TCP SYN to port 443, TCP ACK to port 80, and an ICMP timestamp request by default" -> man nmap
      set_kb_item( name:"/tmp/ping/ICMP", value:1 );
      exit( 0 );
    }
  }

  if( "yes" >< icmp_ping || "yes" >< arp_ping ) {

    argv_icmp = argv;
    argv_icmp[x++] = "-PE";
    argv_icmp[x++] = ip;

    res = pread( cmd:"nmap", argv:argv_icmp );

    if( res && egrep( pattern:pattern, string:res ) && "Host seems down" >!< res ) {
      if( "yes" >< report_up || "yes" >< log_output ) {
        report = "";
        if( "received arp-response" >< res )
          reason = 'ARP';
        else
          reason = 'ICMP';

        if( "yes" >< report_up )
          report += 'Host is up (successful ' + reason + ' ping), Method: nmap\n';
        if( "yes" >< log_output )
          report += 'nmap command: ' + join( list:argv_icmp ) + '\n' + res;
        log_message( data:report, port:0 );
      }
      set_kb_item( name:"/tmp/ping/ICMP", value:1 );
      exit( 0 );
    } else if( res && "Nmap done" >< res && "Host seems down" >< res ) {
      # For later use in e.g. os_fingerprint.nasl
      if( TARGET_IS_IPV6() )
        set_kb_item( name:"ICMPv6/EchoRequest/failed", value:TRUE );
      else
        set_kb_item( name:"ICMPv4/EchoRequest/failed", value:TRUE );
    }
  }

  if( "yes" >< tcp_ping ) {

    argv_tcp = argv;

    # Ports from nmap 7.00 --top-ports 20 (nmap -top-ports=20 -oX -)
    pa_ports = '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080';
    nmap_pa_additional_ports = script_get_preference("nmap additional ports for -PA");

    if( strlen( nmap_pa_additional_ports ) > 0 ) {
      nmap_pa_additional_ports = str_replace( string:nmap_pa_additional_ports, find:" ", replace:"" );
      if( ! check_pa_port_list( list:nmap_pa_additional_ports ) ) {
        log_message( data:'nmap additional ports for -PA has wrong format or contains an invalid port and was ignored. Please use a\ncomma separated list of ports without spaces. Example: 8080,3128,8000', port:0 );
        nmap_pa_additional_ports = '';
      } else {
        pa_ports += ',' + nmap_pa_additional_ports;
      }
    }

    if( "yes" >< tcp_syn_ping_only ) {
      run_tcp_syn_ping( argv:argv, pa_ports:pa_ports, ip:ip, pattern:pattern, report_up:report_up, log_output:log_output );
    } else {

      argv_tcp[x++] = '-PA' + pa_ports;
      argv_tcp[x++] = ip;

      res = pread( cmd:"nmap", argv:argv_tcp );

      if( res && egrep( pattern:pattern, string:res ) && "Host seems down" >!< res ) {
        if( "yes" >< report_up || "yes" >< log_output ) {
          report = "";
          if( "yes" >< report_up )
            report += 'Host is up (successful TCP service ping), Method: nmap\n';
          if( "yes" >< log_output )
            report += 'nmap command: ' + join( list:argv_tcp ) + '\n' + res;
          log_message( data:report, port:0 );
        }
        set_kb_item( name:"/tmp/ping/TCP", value:1 );
        exit( 0 );
      } else {
        if( "yes" >< tcp_syn_ping ) {
          run_tcp_syn_ping( argv:argv, pa_ports:pa_ports, ip:ip, pattern:pattern, report_up:report_up, log_output:log_output );
        }
      }
    }
  }
} else {

  if( "yes" >< icmp_ping ) {

    # Try ICMP (Ping) first

    if( TARGET_IS_IPV6() ) {

      # ICMPv6
      IP6_v = 0x60;
      IP6_P = 0x3a;#ICMPv6
      IP6_HLIM = 0x40;
      ICMP_ID = rand() % 65536;

      myhost = this_host();

      ip6_packet = forge_ipv6_packet( ip6_v:IP6_v,
                                      ip6_p:IP6_P,
                                      ip6_plen:20,
                                      ip6_hlim:IP6_HLIM,
                                      ip6_src:myhost,
                                      ip6_dst:get_host_ip() );
      d = rand_str( length:56 );
      icmp = forge_icmp_v6_packet( ip6:ip6_packet,
                                   icmp_type:128,
                                   icmp_code:0,
                                   icmp_seq:0,
                                   icmp_id:ICMP_ID,
                                   icmp_cksum:-1,
                                   data:d );
      filter = "icmp6 and dst host " + myhost + " and src host " + get_host_ip()  + " and ip6[40] = 129";

      ret = NULL;
      attempt = 2;

      while( !ret && attempt-- ) {
        ret = send_v6packet( icmp, pcap_active:TRUE, pcap_filter:filter );
        if( ret ) {
          if( "yes" >< report_up ) {
            log_message( data:"Host is up (successful ICMP ping), Method: internal", port:0 );
          }
          set_kb_item( name:"/tmp/ping/ICMP", value:1 );
          exit( 0 );
        }
      }
      # For later use in e.g. os_fingerprint.nasl
      set_kb_item( name:"ICMPv6/EchoRequest/failed", value:TRUE );
    } else {

      # ICMPv4
      ICMP_ECHO_REQUEST = 8;
      IP_ID = 0xBABA;
      ICMP_ID = rand() % 65536;

      data = raw_string( 0x0c, 0xf5, 0xf3, 0x4a, 0x88, 0x39, 0x08, 0x00, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
                         0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
                         0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
                         0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37 );

      ip_packet = forge_ip_packet( ip_tos:6,
                                   ip_id:IP_ID,
                                   ip_off:IP_DF,
                                   ip_p:IPPROTO_ICMP,
                                   ip_src:this_host() );

      icmp_packet = forge_icmp_packet( icmp_type:ICMP_ECHO_REQUEST,
                                       icmp_code:123,
                                       icmp_seq:256,
                                       icmp_id:ICMP_ID,
                                       data:data,
                                       ip:ip_packet );
      attempt = 2;
      ret = NULL;

      filter = "icmp and dst host " + this_host() + " and src host " + get_host_ip() + " and icmp[0] = 0 " + " and icmp[4:2] = " + ICMP_ID;

      while( ! ret && attempt-- ) {
        ret = send_packet( icmp_packet, pcap_active:TRUE, pcap_filter:filter, pcap_timeout:3 );
        if( ret ) {
          if( "yes" >< report_up ) {
            log_message( data:"Host is up (successful ICMP ping), Method: internal", port:0 );
          }
          set_kb_item( name:"/tmp/ping/ICMP", value:1 );
          exit( 0 );
        }
      }
      # For later use in e.g. os_fingerprint.nasl
      set_kb_item( name:"ICMPv4/EchoRequest/failed", value:TRUE );
    }
  }

  if( "yes" >< tcp_ping ) {
    # ICMP fails. Try TCP SYN
    if( tcp_ping() ) {
      if( "yes" >< report_up ) {
        log_message( data:"Host is up (successful TCP service ping), Method: internal", port:0 );
      }
      set_kb_item( name:"/tmp/ping/TCP", value:1 );
      exit( 0 );
    }
  }
}

# Host seems to be dead.
register_host_detail( name:"dead", value:1 );

if( "yes" >< report_dead ) {
  data = string( "The remote host ", get_host_ip(), " was considered as dead.\n" );
  log_message( data:data, port:0 );
}

if( "yes" >< mark_dead ) {
  set_kb_item( name:"Host/dead", value:TRUE );
}

exit( 0 );
