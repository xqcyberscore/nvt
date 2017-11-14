###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_http_os_detection.nasl 7718 2017-11-09 15:45:46Z cfischer $
#
# HTTP OS Identification
#
# Authors:
# Christian Fischer <info@schutzwerk.com>
#
# Copyright:
# Copyright (c) 2015 SCHUTZWERK GmbH
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
###############################################################################

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.111067");
  script_version("$Revision: 7718 $");
  script_tag(name:"last_modification", value:"$Date: 2017-11-09 16:45:46 +0100 (Thu, 09 Nov 2017) $");
  script_tag(name:"creation_date", value:"2015-12-10 16:00:00 +0100 (Thu, 10 Dec 2015)");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:N/I:N/A:N");
  script_tag(name:"cvss_base", value:"0.0");
  script_name("HTTP OS Identification");
  script_category(ACT_GATHER_INFO);
  script_family("Product detection");
  script_copyright("This script is Copyright (C) 2015 SCHUTZWERK GmbH");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name:"summary", value:"This script performs HTTP based OS detection from the HTTP/PHP banner or default test pages.");

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");
include("http_func.inc");
include("http_keepalive.inc");

SCRIPT_DESC = "HTTP OS Identification";

port = get_http_port( default:80 );
banner = get_http_banner( port:port );

if( banner && banner = egrep( pattern:"^Server:(.*)$", string:banner, icase:TRUE ) ) {

  banner_type = "HTTP Server banner";

  if( banner == 'Server: CPWS\r\n' ) {
    register_and_report_os( os:"Check Point Gaia", cpe:"cpe:/o:checkpoint:gaia_os", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Embedded Linux
  if( "MoxaHttp" >< banner ) {
    register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "NetApp" >< banner ) {
    # e.g. Server: NetApp/7.3.7 or Server: NetApp//8.2.3P3
    version = eregmatch( pattern:"NetApp//?([0-9a-zA-Z.]+)", string:banner );
    if( ! isnull( version[1] ) ) {
      register_and_report_os( os:"NetApp Data ONTAP", version:version[1], cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"NetApp Data ONTAP", cpe:"cpe:/o:netapp:data_ontap", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }

  # UPS / USV on embedded OS
  if( "ManageUPSnet Web Server" >< banner ) {
    register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Examples:
  # Server: Jetty/5.1.10 (Windows Server 2008/6.1 amd64 java/1.6.0_07
  # Server: Jetty/3.1.8 (Windows 7 6.1 x86)
  # Server: Jetty/5.1.10 (Windows Server 2008 R2/6.1 amd64 java/1.6.0_31
  # Server: Jetty/5.1.15 (Linux/2.6.27.45-crl i386 java/1.5.0
  if( "Jetty/" >< banner ) {
    if( "(Windows" >< banner ) {
      if( "(Windows Server 2016" >< banner ) {
        register_and_report_os( os:"Microsoft Windows Server 2016", cpe:"cpe:/o:microsoft:windows_server_2016", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows 10" >< banner ) {
        register_and_report_os( os:"Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows_10", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows Server 2012 R2" >< banner ) {
        register_and_report_os( os:"Microsoft Windows Server 2012 R2", cpe:"cpe:/o:microsoft:windows_server_2012:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows 8.1" >< banner ) {
        register_and_report_os( os:"Microsoft Windows 8.1", cpe:"cpe:/o:microsoft:windows_8.1", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows Server 2012" >< banner ) {
        register_and_report_os( os:"Microsoft Windows Server 2012", cpe:"cpe:/o:microsoft:windows_server_2012", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows 8" >< banner ) {
        register_and_report_os( os:"Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows_8", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows Server 2008 R2" >< banner ) {
        register_and_report_os( os:"Microsoft Windows Server 2008 R2", cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows 7" >< banner ) {
        register_and_report_os( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows Server 2008" >< banner ) {
        register_and_report_os( os:"Microsoft Windows Server 2008", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows Vista" >< banner ) {
        register_and_report_os( os:"Microsoft Windows Vista", cpe:"cpe:/o:microsoft:windows_vista", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows Server 2003" >< banner ) {
        register_and_report_os( os:"Microsoft Windows Server 2003", cpe:"cpe:/o:microsoft:windows_server_2003", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows XP" >< banner ) {
        register_and_report_os( os:"Microsoft Windows XP Professional", cpe:"cpe:/o:microsoft:windows_xp", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      if( "(Windows 2000" >< banner ) {
        register_and_report_os( os:"Microsoft Windows 2000", cpe:"cpe:/o:microsoft:windows_2000", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
        exit( 0 );
      }
      register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      # nb: We also want to report an unknown OS if none of the above patterns for Windows is matching
      register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_banner", port:port );
      exit( 0 );
    }
    if( "(Linux" >< banner ) {
      version = eregmatch( pattern:"\(Linux/([0-9.]+)", string:banner );
      if( ! isnull( version[1] ) ) {
        register_and_report_os( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      exit( 0 );
    }
  }

  if( "HPE-iLO-Server" >< banner ) {
    register_and_report_os( os:"HP iLO", cpe:"cpe:/o:hp:integrated_lights-out", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "AirTunes" >< banner ) {
    register_and_report_os( os:"Apple TV", cpe:"cpe:/o:apple:tv", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Cisco Secure Access Control Server
  if( banner =~ "ACS ([0-9.]+)" ) {
    register_and_report_os( os:"Cisco", cpe:"cpe:/o:cisco", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Microsoft-HTTPAPI" >< banner || ( "Apache" >< banner && ( "(Win32)" >< banner || "(Win64)" >< banner ) ) ) {
    register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
  }

  # https://en.wikipedia.org/wiki/Internet_Information_Services#History
  # Some IIS versions are shipped with two OS variants so registering both here
  if( "Microsoft-IIS" >< banner ) {
    version = eregmatch( pattern:"Microsoft-IIS/([0-9.]+)", string:banner );
    if( ! isnull( version[1] ) && version[1] == "10.0" ) {
      register_and_report_os( os:"Microsoft Windows Server 2016", cpe:"cpe:/o:microsoft:windows_server_2016", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      register_and_report_os( os:"Microsoft Windows 10", cpe:"cpe:/o:microsoft:windows_10", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    if( ! isnull( version[1] ) && version[1] == "8.5" ) {
      register_and_report_os( os:"Microsoft Windows Server 2012 R2", cpe:"cpe:/o:microsoft:windows_server_2012:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      register_and_report_os( os:"Microsoft Windows 8.1", cpe:"cpe:/o:microsoft:windows_8.1", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    if( ! isnull( version[1] ) && version[1] == "8.0" ) {
      register_and_report_os( os:"Microsoft Windows Server 2012", cpe:"cpe:/o:microsoft:windows_server_2012", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      register_and_report_os( os:"Microsoft Windows 8", cpe:"cpe:/o:microsoft:windows_8", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    if( ! isnull( version[1] ) && version[1] == "7.5" ) {
      register_and_report_os( os:"Microsoft Windows Server 2008 R2", cpe:"cpe:/o:microsoft:windows_server_2008:r2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      register_and_report_os( os:"Microsoft Windows 7", cpe:"cpe:/o:microsoft:windows_7", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    if( ! isnull( version[1] ) && version[1] == "7.0" ) {
      register_and_report_os( os:"Microsoft Windows Server 2008", cpe:"cpe:/o:microsoft:windows_server_2008", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      register_and_report_os( os:"Microsoft Windows Vista", cpe:"cpe:/o:microsoft:windows_vista", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    if( ! isnull( version[1] ) && version[1] == "6.0" ) {
      register_and_report_os( os:"Microsoft Windows Server 2003", cpe:"cpe:/o:microsoft:windows_server_2003", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      register_and_report_os( os:"Microsoft XP Professional x64", cpe:"cpe:/o:microsoft:windows_xp:::x64", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    if( ! isnull( version[1] ) && version[1] == "5.1" ) {
      register_and_report_os( os:"Microsoft Windows XP Professional", cpe:"cpe:/o:microsoft:windows_xp", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    if( ! isnull( version[1] ) && version[1] == "5.0" ) {
      register_and_report_os( os:"Microsoft Windows 2000", cpe:"cpe:/o:microsoft:windows_2000", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    if( ! isnull( version[1] ) && version[1] == "4.0" ) {
      register_and_report_os( os:"Microsoft Windows NT 4.0 Option Pack", cpe:"cpe:/o:microsoft:windows_nt:4.0", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    if( ! isnull( version[1] ) && version[1] == "3.0" ) {
      register_and_report_os( os:"Microsoft Windows NT 4.0 SP2", cpe:"cpe:/o:microsoft:windows_nt:4.0:sp2", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    if( ! isnull( version[1] ) && version[1] == "2.0" ) {
      register_and_report_os( os:"Microsoft Windows NT 4.0", cpe:"cpe:/o:microsoft:windows_nt:4.0", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    if( ! isnull( version[1] ) && version[1] == "1.0" ) {
      register_and_report_os( os:"Microsoft Windows NT 3.51", cpe:"cpe:/o:microsoft:windows_nt:3.51", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
      exit( 0 );
    }
    register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
  }

  if( "Apache" >< banner || "nginx" >< banner || "lighttpd" >< banner ) {

    if( "(SunOS," >< banner || "(SunOS)" >< banner ) {
      register_and_report_os( os:"SunOS", cpe:"cpe:/o:sun:sunos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "/NetBSD" >< banner ) {
      register_and_report_os( os:"NetBSD", cpe:"cpe:/o:netbsd:netbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "(FreeBSD)" >< banner || "-freebsd-" >< banner  ) {
      register_and_report_os( os:"FreeBSD", cpe:"cpe:/o:freebsd:freebsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "OpenBSD" >< banner ) {
      register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "(Debian)" >< banner || "(Debian GNU/Linux)" >< banner || "devel-debian" >< banner || "~dotdeb+" >< banner || "(Raspbian)" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "(Gentoo)" >< banner || "-gentoo" >< banner ) {
      register_and_report_os( os:"Gentoo", cpe:"cpe:/o:gentoo:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "(Linux/SUSE)"  >< banner || "/SuSE)" >< banner ) {
      register_and_report_os( os:"SUSE Linux", cpe:"cpe:/o:novell:suse_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "(CentOS)" >< banner ) {
      if( "Apache/2.4.6 (CentOS)" >< banner ) {
        register_and_report_os( os:"CentOS", version:"7", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else if( "Apache/2.2.15 (CentOS)" >< banner ) {
        register_and_report_os( os:"CentOS", version:"6", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      } else {
        register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      }
      exit( 0 );
    }

    if( "(Ubuntu)" >< banner ) {
      register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "(Red Hat Enterprise Linux)" >< banner ) {
      register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "(Red Hat)" >< banner ) {
      register_and_report_os( os:"Redhat Linux", cpe:"cpe:/o:redhat:linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "(Fedora)" >< banner ) {
      register_and_report_os( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "(Oracle)" >< banner ) {
      register_and_report_os( os:"Oracle Linux", cpe:"cpe:/o:oraclelinux:oraclelinux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "(Unix)" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "mini-http" >< banner && "(unix)" >< banner ) {
      register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "(Univention)" >< banner ) {
      register_and_report_os( os:"Univention Corporate Server", cpe:"cpe:/o:univention:univention_corporate_server", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }
  }

  if( "Nginx on Linux Debian" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # nb: The +deb banner (which is using something like +deb1~bpo8) doesn't match directly to the OS
  if( "ZNC" >< banner && ( "~bpo" >< banner || "+deb" >< banner ) ) {
    # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
    if( "~bpo7" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else if( "~bpo8" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else if( "~bpo9" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }

  if( "Nginx centOS" >< banner ) {
    register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "Nginx (OpenBSD)" >< banner || ( "Lighttpd" >< banner && "OpenBSD" >< banner ) ) {
    register_and_report_os( os:"OpenBSD", cpe:"cpe:/o:openbsd:openbsd", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # Proxmox VE is only running on unix-like OS
  if( egrep( pattern:"^Server: pve-api-daemon/([0-9.]+)", string:banner, icase:TRUE ) ) {
    register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  # SERVER: POSIX, UPnP/1.0, Intel MicroStack/1.0.2126
  # Server: POSIX, UPnP/1.0, Intel MicroStack/1.0.2777
  if( "server: posix, upnp/1.0, intel microstack" >< tolower( banner ) ) {
    register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( egrep( pattern:"^Server: Linux", string:banner, icase:TRUE ) ) {
    version = eregmatch( pattern:"Linux/([0-9.x]+)", string:banner );
    if( ! isnull( version[1] ) ) {
      register_and_report_os( os:"Linux", version:version[1], cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }
  register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"http_banner", port:port );
}

# TODO: If the server is reporting "Server: (Ubuntu)" but a more detailed X-Powered-By the first wins and we currently won't reach the part here
phpList = get_kb_list( "www/" + port + "/content/extensions/php" );
if( phpList ) phpFiles = make_list( phpList );
phpinfoBanner = get_kb_item( "php/phpinfo/phpversion/" + port );

if( phpFiles[0] ) {
  phpBanner = get_http_banner( port:port, file:phpFiles[0] );
} else {
  phpBanner = get_http_banner( port:port, file:"/index.php" );
}

if( phpBanner && phpBanner = egrep( pattern:"^X-Powered-By: PHP/(.*)$", string:phpBanner, icase:TRUE ) ) {

  banner_type = "PHP Server banner";

  # nb: The naming of the sury.org PHP banners have some special syntax like: PHP/7.1.7-1+0~20170711133844.5+jessie~1.gbp5284f4
  # Using it separately as this still a too common pattern
  if( ".gbp" >< phpBanner ) {
    if( "+squeeze" >< phpBanner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "+wheezy" >< phpBanner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "+jessie" >< phpBanner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "+stretch" >< phpBanner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"9", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }
  }

  # e.g. X-Powered-By: PHP/5.4.24-1+sury.org~lucid+1 or X-Powered-By: PHP/7.1.8-2+ubuntu14.04.1+deb.sury.org+4
  if( "sury.org" >< phpBanner ) {
    version = eregmatch( pattern:"\+ubuntu([0-9.]+)", string:phpBanner );
    if( ! isnull( version[1] ) ) {
      register_and_report_os( os:"Ubuntu", version:version[1], cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( "~lucid" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"10.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~maverick" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"10.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~natty" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"11.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~oneiric" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"11.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~precise" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"12.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~quantal" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"12.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~raring" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"13.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~saucy" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"13.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~trusty" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"14.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );	
    } else if( "~utopic" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"14.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~vivid" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"15.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~wily" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"15.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~xenial" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"16.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~yakkety" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"16.10", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    } else if( "~zesty" >< phpBanner ) {
      register_and_report_os( os:"Ubuntu", version:"17.04", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }
  }

  if( "ubuntu" >< phpBanner ) {
    register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "+deb" >< phpBanner || "~dotdeb+" >< phpBanner || "~deb" >< phpBanner || "~bpo" >< phpBanner ) {

    # nb: The order matters in case of backports which might have something like +deb9~bpo8
    if( "+deb6" >< phpBanner || "~deb6" >< phpBanner || "~dotdeb+squeeze" >< phpBanner || "~bpo6" >< phpBanner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    # nb: Starting with Wheezy (7.x) we have minor releases within the version so we don't use an exact version like 7.0 as we can't differ between the OS in the banner here
    } else if( "+deb7" >< phpBanner || "~dotdeb+7" >< phpBanner || "~bpo7" >< phpBanner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"7", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else if( "+deb8" >< phpBanner || "~dotdeb+8" >< phpBanner || "~bpo8" >< phpBanner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:phpBanner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }

  register_unknown_os_banner( banner:phpBanner, banner_type_name:banner_type, banner_type_short:"php_banner", port:port );
}

buf = http_get_cache( item:"/", port:port );
if( buf && buf =~ "^HTTP/1\.[01] 200" ) {

  banner_type = "HTTP Server default page";

  if( "<title>Test Page for the Apache HTTP Server" >< buf ||
      "<title>Apache HTTP Server Test Page" >< buf ||
      "<title>Test Page for the Nginx HTTP Server" >< buf ) {

    check = "on Red Hat Enterprise Linux</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Red Hat Enterprise Linux", cpe:"cpe:/o:redhat:enterprise_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "powered by CentOS</title>";

    if( check >< buf ) {
      register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on CentOS</title>";

    if( check >< buf ) {
      register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on Fedora Core</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Fedora Core", cpe:"cpe:/o:fedoraproject:fedora_core", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on Fedora</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "powered by Ubuntu</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "powered by Debian</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on Mageia</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Mageia", cpe:"cpe:/o:mageia:linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on EPEL</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on Scientific Linux</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Scientific Linux", cpe:"cpe:/o:scientificlinux:scientificlinux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on the Amazon Linux AMI</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Amazon Linux", cpe:"cpe:/o:amazon:linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on CloudLinux</title>";

    if( check >< buf ) {
      register_and_report_os( os:"CloudLinux", cpe:"cpe:/o:cloudlinux:cloudlinux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on SLES Expanded Support Platform</title>";

    if( check >< buf ) {
      register_and_report_os( os:"SUSE Linux Enterprise Server", cpe:"cpe:/o:suse:linux_enterprise_server", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on Oracle Linux</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Oracle Linux", cpe:"cpe:/o:oraclelinux:oraclelinux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( check = eregmatch( string:buf, pattern:"<title>(Test Page for the (Apache|Nginx) HTTP Server|Apache HTTP Server Test Page) (powered by|on).*</title>" ) ) {
      register_unknown_os_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
    }
  }

  if( "<TITLE>Welcome to Jetty" >< buf ) {

    check = "on Debian</TITLE>";

    if( check >< buf ) {
      register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( check = eregmatch( string:buf, pattern:"<TITLE>Welcome to Jetty.*on.*</TITLE>" ) ) {
      register_unknown_os_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
    }
  }

  if( "<title>Welcome to nginx" >< buf ) {

    check = "on Debian!</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on Ubuntu!</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on Fedora!</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Fedora", cpe:"cpe:/o:fedoraproject:fedora", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "on Slackware!</title>";

    if( check >< buf ) {
      register_and_report_os( os:"Slackware", cpe:"cpe:/o:slackware:slackware_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( check = eregmatch( string:buf, pattern:"<title>Welcome to nginx on.*!</title>" ) ) {
      register_unknown_os_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
    }
  }

  if( "<title>Apache2" >< buf && "Default Page: It works</title>" >< buf ) {

    check = "<title>Apache2 Debian Default Page";

    if( check >< buf ) {
      register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "<title>Apache2 Ubuntu Default Page";

    if( check >< buf ) {
      register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    check = "<title>Apache2 centos Default Page";

    if( check >< buf ) {
      register_and_report_os( os:"CentOS", cpe:"cpe:/o:centos:centos", banner_type:banner_type, port:port, banner:check, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }

    if( check = eregmatch( string:buf, pattern:"<title>Apache2 .* Default Page: It works</title>" ) ) {
      register_unknown_os_banner( banner:check[0], banner_type_name:banner_type, banner_type_short:"http_test_banner", port:port );
    }
  }
}

# CUPS is running only on macOS and other UNIX-like operating systems
if( ( banner && "Server: CUPS/" >< banner ) || buf =~ "<TITLE>(Forbidden|Home|Not Found|Bad Request) - CUPS.*</TITLE>" ) {
  register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:chomp( banner ) + " and/or CUPS title page", desc:SCRIPT_DESC, runs_key:"unixoide" );
}

# nb: Using buf here as the previously "banner" is currently overwritten at the top if no Server: header exists
if( buf && user_agent = egrep( pattern:"^User-Agent:(.*)$", string:buf, icase:TRUE ) ) {

  banner_type = "HTTP Server banner";

  # LibreOffice Online WebSocket server: https://github.com/LibreOffice/online/blob/master/wsd/README
  # This is the only service i have seen so far which is responding with a User-Agent: header
  # nb: loolwsd is only running on Linux/Unix
  if( "LOOLWSD WOPI Agent" >< user_agent ) {
    register_and_report_os( os:"Linux/Unix", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:user_agent, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }
  register_unknown_os_banner( banner:user_agent, banner_type_name:banner_type, banner_type_short:"http_banner", port:port );
}

exit( 0 );