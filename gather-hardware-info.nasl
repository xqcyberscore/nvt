###############################################################################
# OpenVAS Vulnerability Test
# $Id: gather-hardware-info.nasl 8033 2017-12-07 15:25:32Z cfischer $
#
# Gather Linux Hardware Information
#
# Authors:
# Henri Doreau <henri.doreau@greenbone.net>
#
# Copyright:
# Copyright (c) 2011 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License Version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.103996");
  script_version("$Revision: 8033 $");
  script_tag(name:"last_modification", value:"$Date: 2017-12-07 16:25:32 +0100 (Thu, 07 Dec 2017) $");
  script_tag(name:"creation_date", value:"2011-04-05 14:24:03 +0200 (Tue, 05 Apr 2011)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("Gather Linux Hardware Information");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2011 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("login/SSH/success");
  script_exclude_keys("ssh/no_linux_shell");

  script_tag(name:"summary", value:"This script attempts to gather information about the hardware configuration
  from a linux host and stores the results in the KB.");

  script_tag(name:"qod_type", value:"package");

  exit(0);
}

include("host_details.inc");
include("ssh_func.inc");

SCRIPT_DESC = "Gather Linux Hardware Information";

sock = ssh_login_or_reuse_connection();
if( ! sock ) exit( 0 );

# -- Get CPU information -- #
cpuinfo = ssh_cmd( socket:sock, cmd:"cat /proc/cpuinfo" );
cpus = make_array();
cpunumber = 0;
foreach line( split( cpuinfo ) ) {

  if( line =~ "^processor" ) cpunumber++;

  v = eregmatch( string:line, pattern:"^(model name.*: )(.*).$", icase:TRUE );
  if( ! isnull( v ) ) {
    if( isnull( cpus[v[2]] ) ) {
      cpus[v[2]] = 1;
    } else {
      cpus[v[2]]++;
    }
  }
}

# -- Get the systems architecture -- #
archinfo = ssh_cmd( socket:sock, cmd:"uname -m" );
arch = "";
if( egrep( string:archinfo, pattern:"^(x86_64|i386|i486|i586|i686|sun4u|unknown|armv7l|armv8|ia64|alpha|amd64|arm|armeb|armel|hppa|m32r|m68k|mips|mipsel|powerpc|ppc64|s390|s390x|sh3|sh3eb|sh4|sh4eb|sparc)$" ) ) {
  arch = archinfo;
  set_kb_item( name:"ssh/login/arch", value:arch );
}

# -- Get memory information -- #
meminfo = ssh_cmd( socket:sock, cmd:"cat /proc/meminfo" );
memtotal = "";
foreach line( split( meminfo ) ) {
  v = eregmatch( string:line, pattern:"^(MemTotal:[ ]+)([0-9]+ kB).$", icase:TRUE );
  if (!isnull(v)) {
    memtotal = v[2];
    break;
  }
}

# -- Get network interfaces information -- #
ifconfig = ssh_cmd( socket:sock, cmd:"/sbin/ifconfig" );

interfaces = split( ifconfig, sep:'\n\n', keep:FALSE );
netinfo = "";
host_ip = get_host_ip();

foreach interface( interfaces ) {

  x = 0;
  ip_str = '';

  if( "Loopback" >< interface ) continue;

  lines = split( interface );

  foreach line( lines ) {

    v = eregmatch( string:line, pattern:"^[^ ].*|.*inet[6]? addr.*|^$" );
    if( ! isnull( v ) ) {
      netinfo += v[0];
    }

    if( "HWaddr" >< line ) {

      mac = eregmatch( pattern:"HWaddr ([0-9a-fA-F:]{17})", string:line );
      nic = eregmatch( pattern:"(^[^ ]+)", string:line );

      z = x + 1;
      while( ip = eregmatch( pattern:"inet[6]? addr:[ ]?([^ ]+)", string:lines[z] ) ) {
        if( ! isnull( ip[1] ) ) {
          ip_str += ip[1] + ';';
        }
        z++;
      }

      ip_str = substr( ip_str, 0, strlen( ip_str ) - 2 );

      if( ! isnull( mac ) ) {
        num_ifaces++;
        replace_kb_item( name:"ssh/login/net_iface/num_ifaces", value:num_ifaces );
        if( host_ip >< lines[x+1] ) {
          register_host_detail( name:"MAC", value:mac[1], desc:SCRIPT_DESC );
          set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_mac", value:mac[1] );
          if( ! isnull( nic[1] ) ) {
            target_nic = nic[1];
            register_host_detail( name:"NIC", value:nic[1], desc:SCRIPT_DESC );
            set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_name", value:nic[1] );
            if( strlen( ip_str ) > 0 ) {
              register_host_detail( name:"NIC_IPS", value:ip_str, desc:SCRIPT_DESC );
              set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_ips", value:ip_str );
            }
          }
        }

        if( ! isnull( nic[1] ) && nic[1] != target_nic ) {
          set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_mac", value:mac[1] );
          set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_name", value:nic[1] );
          set_kb_item( name:"ssh/login/net_iface/" + num_ifaces + "/iface_ips", value:ip_str );
          register_host_detail( name:"MAC-Ifaces", value:nic[1] + '|' + mac[1] + '|' + ip_str, desc:SCRIPT_DESC );
        }
      } else {
        iv_mac = eregmatch( pattern:"HWaddr ([^ \n]+)", string:line );
        if( ! isnull( iv_mac[1] ) && ! isnull( nic[1] ) ) {
          register_host_detail( name:"BROKEN_MAC-Iface", value:nic[1] + '|' + iv_mac[1] + '|' + ip_str, desc:SCRIPT_DESC );
        }
      }
    }
    x++;
  }
}

# -- store results in the host details DB -- #
if( cpunumber ) {
  cpu_str = '';
  foreach cputype( keys( cpus ) ) {
    if( cpu_str != '' ) {
      cpu_str += '\n';
    }
    cpu_str += string( cpus[cputype], " ", cputype );
  }
  register_host_detail( name:"cpuinfo", value:cpu_str, desc:SCRIPT_DESC );
}

if( archinfo != "" ) {
  register_host_detail( name:"archinfo", value:archinfo, desc:SCRIPT_DESC );
}

if( memtotal != "" ) {
  register_host_detail( name:"meminfo", value:memtotal, desc:SCRIPT_DESC );
}

if( netinfo != "" ) {
  register_host_detail( name:"netinfo", value:netinfo, desc:SCRIPT_DESC );
}

exit( 0 );
