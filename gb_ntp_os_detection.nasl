# Copyright (C) 2019 Greenbone Networks GmbH
#
# SPDX-License-Identifier: GPL-2.0-or-later
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.108590");
  script_version("2019-06-06T14:25:19+0000");
  script_tag(name:"last_modification", value:"2019-06-06 14:25:19 +0000 (Thu, 06 Jun 2019)");
  script_tag(name:"creation_date", value:"2019-06-01 07:09:18 +0000 (Sat, 01 Jun 2019)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("NTP Server OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("Copyright (C) 2019 Greenbone Networks GmbH");
  script_dependencies("ntp_open.nasl");
  script_mandatory_keys("ntp/system_banner/available");

  script_tag(name:"summary", value:"This script performs NTP server based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("misc_func.inc");

SCRIPT_DESC = "NTP Server OS Identification";
BANNER_TYPE = "NTP Server banner";

port = get_port_for_service( default:123, ipproto:"udp", proto:"ntp" );

if( ! banner = get_kb_item( "ntp/" + port + "/system_banner" ) )
  exit( 0 );

# nb: There are around 23k of such systems available on shodan and it's
# not clear what's behind this pattern.
if( banner == "/" )
  exit( 0 );

if( "linux" >< tolower( banner ) ) {

  # Linux/4.9.72-gentoo
  # Linux/2.6.24-gentoo-r4
  if( "-gentoo" >< banner ) {
    register_and_report_os( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

  # Linux/2.6.24-ARCH
  # Linux/5.0.9-arch1-1-ARCH
  # Linux/4.12.8-2-ARCH
  # Linux/3.2.8-1-ARCH
  else if( "-arch" >< tolower( banner ) ) {
    register_and_report_os( os:"Arch Linux", cpe:"cpe:/o:archlinux:archlinux", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }

  # Linux2.4.18_mvl30-amazon
  else if( "-amazon" >< tolower( banner ) ) {
    register_and_report_os( os:"Amazon Linux", cpe:"cpe:/o:amazon:linux", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {

    # Linux/2.6.35em1-g9733209
    # Linux2.4.20_mvl31-bcm95836cpci
    # Linux2.2.13
    version = eregmatch( pattern:"Linux/?([0-9.]+)", string:banner );
    if( ! isnull( version[1] ) ) {
      register_and_report_os( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
  }
}

else if( "windows" >< tolower( banner ) || banner =~ "^win" ) {

  # Win2008R2 x64
  # Win2016
  # Win2012R2
  # Win2003
  # or just: Windows
  if( banner =~ "win2008r2" ) {
    register_and_report_os( os:"Microsoft Windows Server 2008 R2", cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"windows" );
  } else if( banner =~ "win2008" ) {
    register_and_report_os( os:"Microsoft Windows Server 2008", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"windows" );
  } else if( banner =~ "win2016" ) {
    register_and_report_os( os:"Microsoft Windows Server 2016", cpe:"cpe:/o:microsoft:windows_server_2016", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"windows" );
  } else if( banner =~ "win2012r2" ) {
    register_and_report_os( os:"Microsoft Windows Server 2012 R2", cpe:"cpe:/o:microsoft:windows_server_2012:r2", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"windows" );
  } else if( banner =~ "win2012" ) {
    register_and_report_os( os:"Microsoft Windows Server 2012", cpe:"cpe:/o:microsoft:windows_server_2012", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"windows" );
  } else if( banner =~ "win2003" ) {
    register_and_report_os( os:"Microsoft Windows Server 2003", cpe:"cpe:/o:microsoft:windows_server_2003", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"windows" );
  } else {
    register_and_report_os( os:banner, cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"windows" );
  }
}

# UNIX
else if( "unix" >< tolower( banner ) ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
}

else if( "freebsd" >< tolower( banner ) ) {

  # FreeBSDJNPR-11.0-20180730.2cd3a6e_buil
  # FreeBSDJNPR-10.3-20170422.348838_build
  # FreeBSD/10.1-RELEASE-p25
  # FreeBSD/11.2-RELEASE-p6
  version = eregmatch( pattern:"FreeBSD(/|JNPR-)([0-9.]+)(-RELEASE-(p[0-9]+))?", string:banner );
  if( ! isnull( version[2] ) && ! isnull( version[4] ) ) {
    register_and_report_os( os:"FreeBSD", version:version[2], patch:version[4], cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( ! isnull( version[2] ) ) {
    register_and_report_os( os:"FreeBSD", version:version[2], cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else if( "netbsd" >< tolower( banner ) ) {

  # NetBSD/8.0
  # NetBSD/6.1.5
  # NetBSD/7.1_STABLE
  # NetBSD/6.99.23
  # NetBSD/6.1_STABLE
  # NetBSD/8.1_RC1
  version = eregmatch( pattern:"NetBSD/([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"NetBSD", version:version[1], cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else if( "openbsd" >< tolower( banner ) ) {

  # OpenBSD/3.2
  # OpenBSD/6.3
  # OpenBSD/6.5
  version = eregmatch( pattern:"OpenBSD/([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"OpenBSD", version:version[1], cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else if( "sunos" >< tolower( banner ) ) {

  # SunOS/5.10
  # SunOS/5.11
  # SunOS/5.8
  version = eregmatch( pattern:"SunOS/([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"SunOS", version:version[1], cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else if( "hp-ux" >< tolower( banner ) ) {

  # HP-UX/
  version = eregmatch( pattern:"HP-UX/([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"HP-UX", version:version[1], cpe:"cpe:/o:hp:hp-ux", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"HP-UX", cpe:"cpe:/o:hp:hp-ux", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else if( "data ontap" >< tolower( banner ) ) {

  # Data ONTAP/8.2.4P1
  # Data ONTAP/8.2.5
  # Data ONTAP/9.4P1
  version = eregmatch( pattern:"Data ONTAP/([0-9.a-zA-Z\-]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"NetApp Data ONTAP", version:version[1], cpe:"cpe:/o:netapp:data_ontap", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else if( "junos" >< tolower( banner ) ) {

  # JUNOS11.4R13.5
  # JUNOS12.1X46-D40.2
  # JUNOS14.2R5-S1.2
  # JUNOS15.1R6.7
  version = eregmatch( pattern:"JUNOS([0-9.a-zA-Z]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"JunOS", version:version[1], cpe:"cpe:/o:juniper:junos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"JunOS", cpe:"cpe:/o:juniper:junos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else if( "secureos" >< tolower( banner ) ) {

  # SecureOS/8.3.2P09
  # SecureOS/7.0.1.03.H15
  # SecureOS/8.1.2
  # SecureOS/8.3.2E178
  # SecureOS/8.3.2P11
  version = eregmatch( pattern:"SecureOS/([0-9.]+)((\.H|P|E)([0-9]+))?", string:banner );
  if( ! isnull( version[1] ) && ! isnull( version[4] ) ) {
    version[3] = str_replace( string:version[3], find:".H", replace:"H" );
    register_and_report_os( os:"Secure64 SecureOS", version:version[1], patch:version[3] + version[4], cpe:"cpe:/o:secure64:secureos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"Secure64 SecureOS", version:version[1], cpe:"cpe:/o:secure64:secureos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Secure64 SecureOS", cpe:"cpe:/o:secure64:secureos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

# sparcv9-wrs-vxworks
# powerpc-wrs-vxworks
# arm-wrs-vxworks
else if( "vxworks" >< tolower( banner ) ) {
  register_and_report_os( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# Darwin/16.7.0
# Darwin7.6.0
# Darwin/9.5.1
# Darwin/8.11.1
# Darwin8.11.0
#
# TODO: We might be able to do a matching between the Darwin version and OS X / iOS:
# https://en.wikipedia.org/wiki/Darwin_(operating_system)#Release_history
else if( banner =~ "Darwin[0-9/]" ) {
  register_and_report_os( os:"Apple Mac OS X / macOS / iOS", cpe:"cpe:/o:apple:mac_os_x", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
}

else if( banner =~ "^QNX" ) {

  # QNX/6.5.0
  # QNX/6.4.1
  # QNX/6.3.2
  version = eregmatch( pattern:"QNX/([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"QNX Neutrino Realtime Operating System", version:version[1], cpe:"cpe:/o:blackberry:qnx_neutrino_rtos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"QNX Neutrino Realtime Operating System", cpe:"cpe:/o:blackberry:qnx_neutrino_rtos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else if( "isilon onefs" >< tolower( banner ) ) {

  # Isilon OneFS/v8.0.1.1
  # Isilon OneFS/v7.2.1.0
  # Isilon OneFS/v8.0.0.6
  # Isilon OneFS/v8.1.0.2
  # Isilon OneFS/v8.0.0.4
  version = eregmatch( pattern:"Isilon OneFS/v([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"Dell EMC Isilon OneFS", version:version[1], cpe:"cpe:/o:emc:isilon_onefs", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Dell EMC Isilon OneFS", cpe:"cpe:/o:emc:isilon_onefs", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else if( banner =~ "^GBOS" ) {

  # GBOS/6.2.12
  # GBOS/6.2.10
  # GBOS/6.2.11
  version = eregmatch( pattern:"GBOS/([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"GTA GB-OS", version:version[1], cpe:"cpe:/o:gta:gb-os", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"GTA GB-OS", cpe:"cpe:/o:gta:gb-os", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

# powerpc-ecos-ecos
# eCos/0x7fffff00
else if( "ecos-ecos" >< tolower( banner ) || banner =~ "^ecos" ) {
  register_and_report_os( os:"eCos RTOS", cpe:"cpe:/o:ecoscentric:ecos_rtos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# BRIX
# nb: Not absolutely clear about this, assuming http://brix-os.sourceforge.net for now
else if( banner =~ "^BRIX" ) {
  register_and_report_os( os:"BRiX", cpe:"cpe:/o:brix:brix", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
}

else if( "eq/os" >< tolower( banner ) ) {

  # EQ/OS_84.118.6-RELEASE-p4
  # EQ/OS_84.118.5-RELEASE-p4
  version = eregmatch( pattern:"EQ/OS_([0-9.]+)(-RELEASE-(p[0-9]+))?", string:banner );
  if( ! isnull( version[1] ) && ! isnull( version[3] ) ) {
    register_and_report_os( os:"Fortinet EQ/OS", version:version[1], patch:version[3], cpe:"cpe:/o:fortinet:eq%2Fos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"Fortinet EQ/OS", version:version[1], cpe:"cpe:/o:fortinet:eq%2Fos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Fortinet EQ/OS", cpe:"cpe:/o:fortinet:eq%2Fos", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else if( "chiaros" >< tolower( banner ) ) {

  # Chiaros/4.10-RELEASE
  version = eregmatch( pattern:"Chiaros/([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"Chiaro Networks Chiaros", version:version[1], cpe:"cpe:/o:chiaro:chiaros", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Chiaro Networks Chiaros", cpe:"cpe:/o:chiaro:chiaros", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else if( "mitautm" >< tolower( banner ) ) {

  # MitaUTM/10.1-RELEASE-p15
  version = eregmatch( pattern:"MitaUTM/([0-9.]+)(-RELEASE-(p[0-9]+))?", string:banner );
  if( ! isnull( version[1] ) && ! isnull( version[3] ) ) {
    register_and_report_os( os:"MitaUTM", version:version[1], patch:version[3], cpe:"cpe:/o:mitautm:mitautm", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"MitaUTM", version:version[1], cpe:"cpe:/o:mitautm:mitautm", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"MitaUTM", cpe:"cpe:/o:mitautm:mitautm", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

# Moscad ACE
# nb: VX-Works based real-time operating system
else if( "moscad ace" >< tolower( banner ) ) {
  register_and_report_os( os:"Motorola Moscad ACE", cpe:"cpe:/o:motorola:moscad_ace_firmware", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# UnixWare5
# nb: The 5 in the banner above is not the actual version, at least the same system had e.g. SCO UnixWare 7.1.4 in the telnet banner.
# As we can't differentiate between the company here we're using the most recent one in the CPE.
else if( "unixware" >< tolower( banner ) ) {
  register_and_report_os( os:"Univel/Novell/SCO/Xinuos UnixWare", cpe:"cpe:/o:xinuos:unixware", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
}

else if( "brickstoros" >< tolower( banner ) ) {

  # BrickStorOS/19.01
  version = eregmatch( pattern:"BrickStorOS/([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"RackTop Systems BrickStor OS", version:version[1], cpe:"cpe:/o:racktopsystems:brickstoros", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"RackTop Systems BrickStor OS", cpe:"cpe:/o:racktopsystems:brickstoros", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

# "VMkernel is a POSIX-like operating system developed by VMware."
else if( banner =~ "^VMkernel" ) {

  # VMkernel/5.5.0
  # VMkernel/6.0.0
  # VMkernel/4.0.0
  # VMkernel/4.1.0
  # VMkernel/5.0.0
  # VMkernel/6.5.0
  # VMkernel/5.1.0
  # VMkernel/3.5.0
  version = eregmatch( pattern:"VMkernel/([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"VMware VMkernel", version:version[1], cpe:"cpe:/o:vmware:vmkernel", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"VMware VMkernel", cpe:"cpe:/o:vmware:vmkernel", banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
}

else {
  # nb: Setting the runs_key to unixoide makes sure that we still schedule NVTs using Host/runs_unixoide as a fallback
  register_and_report_os( os:banner, banner_type:BANNER_TYPE, banner:banner, port:port, proto:"udp", desc:SCRIPT_DESC, runs_key:"unixoide" );
  register_unknown_os_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"ntp_banner", port:port, proto:"udp" );
}

exit( 0 );
