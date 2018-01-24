###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ftp_os_detection.nasl 8503 2018-01-23 16:49:56Z cfischer $
#
# FTP OS Identification
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
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
  script_oid("1.3.6.1.4.1.25623.1.0.105355");
  script_version("$Revision: 8503 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-23 17:49:56 +0100 (Tue, 23 Jan 2018) $");
  script_tag(name:"creation_date", value:"2015-09-15 15:57:03 +0200 (Tue, 15 Sep 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("FTP OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 Greenbone Networks GmbH");
  script_dependencies("find_service.nasl", "find_service_3digits.nasl", "ftpserver_detect_type_nd_version.nasl");
  script_require_ports("Services/ftp", 21);

  script_tag(name:"summary", value:"This script performs FTP banner based OS detection.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("ftp_func.inc");

SCRIPT_DESC = "FTP OS Identification";
BANNER_TYPE = "FTP banner";

port = get_ftp_port( default:21 );

banner = get_ftp_banner( port:port );
if( ! banner  || banner == "" || isnull( banner ) ) exit( 0 );

# 220 VxWorks FTP server (VxWorks 5.3.1 - Secure NetLinx version (1.0)) ready.
if( "VxWorks FTP server" >< banner ) {
  version = eregmatch( pattern:"\(VxWorks ([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"Wind River VxWorks", version:version[1], cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"Wind River VxWorks", cpe:"cpe:/o:windriver:vxworks", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "Network Management Card AOS" >< banner ) {
  version = eregmatch( pattern:"Network Management Card AOS v([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"APC AOS", version:version[1], cpe:"cpe:/o:apc:aos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"APC AOS", cpe:"cpe:/o:apc:aos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( ( "Microsoft FTP Service" >< banner && "WINDOWS SERVER 2003" >< banner ) || "OS=Windows Server 2003;" >< banner ) {
  register_and_report_os( os:"Microsoft Windows Server 2003", cpe:"cpe:/o:microsoft:windows_2003_server", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "MinWin FTP server" >< banner ) {
  register_and_report_os( os:"Microsoft Windows 10 IoT", cpe:"cpe:/o:microsoft:windows_10:::iot", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "OS=Windows 10;" >< banner ) {
  register_and_report_os( os:"Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows_10", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "OS=Windows 8;" >< banner ) {
  register_and_report_os( os:"Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows_8", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "OS=Windows 7;" >< banner ) {
  register_and_report_os( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "OS=Windows XP;" >< banner ) {
  register_and_report_os( os:"Microsoft Windows XP", cpe:"cpe:/o:microsoft:windows_xp", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "ProFTPD" >< banner && "(Windows" >< banner ) {
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

# FileZilla Server currently runs only on Windows
if( "FileZilla Server" >< banner ) {
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "FTP Server for Windows" >< banner || "220 FTP to Windows" >< banner || "FTP/S Server for Windows" >< banner ||
    "Microsoft FTP Service" >< banner || "220 Windows server" >< banner || "220 -Microsoft FTP server" >< banner ||
    "running on Windows " >< banner || "Windows FTP Server" >< banner || "Windows NT XDS FTP server" >< banner ||
    "220 Welcom to Windows" >< banner ) {
  register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "Windows Server 2008 SP2" >< banner ) {
  register_and_report_os( os:"Microsoft Windows Server 2008 SP2", cpe:"cpe:/o:microsoft:windows_server_2008:-:sp2", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "running on Windows Server 2008 R2 Enterprise" >< banner || "OS=Windows Server 2008 R2;" >< banner ) {
  register_and_report_os( os:"Microsoft Windows Server 2008 R2", cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "running on Windows 2008" >< banner ) {
  register_and_report_os( os:"Microsoft Windows 2008", cpe:"cpe:/o:microsoft:windows:2008", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "Windows Server 2012 R2" >< banner ) {
  register_and_report_os( os:"Microsoft Windows Server 2012 R2", cpe:"cpe:/o:microsoft:windows_server_2012:r2", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "OS=Windows Server 2012;" >< banner ) {
  register_and_report_os( os:"Microsoft Windows Server 2012", cpe:"cpe:/o:microsoft:windows_server_2012", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  exit( 0 );
}

if( "ProFTPD" >< banner ) {
  if( "(Debian)" >< banner || "(Raspbian)" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "(Gentoo)" >< banner ) {
    register_and_report_os( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "(powered by SuSE Linux)" ) {
    register_and_report_os( os:"SUSE Linux", cpe:"cpe:/o:novell:suse_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "220-CentOS release" >< banner ) {
    register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "(ubuntu)" >< banner ) {
    register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }
}

if( "This is a Linux PC" >< banner || "Linux FTP Server" >< banner ) {
  register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "220-Red Hat Enterprise Linux Server" >< banner ) {
  register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "220-Welcome to openSUSE" >< banner ) {
  register_and_report_os( os:"openSUSE", cpe:"cpe:/o:novell:opensuse", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "FTP server (NetBSD-ftpd" >< banner ) {
  register_and_report_os( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

if( "220-OpenBSD" >< banner || "FTP server (Version 6.4/OpenBSD/Linux-ftpd-0.17)" >< banner ) {
  register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# FTP server (SunOS 5.8)
if( "FTP server (SunOS" >< banner ) {
  version = eregmatch( pattern:"FTP server \(SunOS ([0-9.]+)", string:banner );
  if( ! isnull( version[1] ) ) {
    register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", version:version[1], banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  } else {
    register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  }
  exit( 0 );
}

if( "220 Solaris FTP Server" >< banner || "(Sun Solaris" >< banner ) {
  register_and_report_os( os:"Sun Solaris", cpe:"cpe:/o:sun:solaris", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# vsFTPd runs only on Unix-like systems
if( "220 (vsFTPd" >< banner ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Pure-FTPd was designed for Unix-like systems. There might be windows systems out but they are probably very rare
if( "Pure-FTPd" >< banner ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# WU-FTPD runs only on Unix-like systems
if( "FTP server (Version wu-" >< banner ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# UPS / USV on embedded OS
if( "ManageUPSnet FTP server" >< banner ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

# Zimbra runs only on Unix-like systems
if( "Zimbra LMTP server ready" >< banner ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:BANNER_TYPE, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
  exit( 0 );
}

register_unknown_os_banner( banner:banner, banner_type_name:BANNER_TYPE, banner_type_short:"ftp_banner", port:port );

exit( 0 );
