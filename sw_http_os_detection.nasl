###############################################################################
# OpenVAS Vulnerability Test
# $Id: sw_http_os_detection.nasl 6210 2017-05-24 15:02:34Z cfi $
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
  script_version("$Revision: 6210 $");
  script_tag(name:"last_modification", value:"$Date: 2017-05-24 17:02:34 +0200 (Wed, 24 May 2017) $");
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

  if( "Microsoft-HTTPAPI" >< banner || "Microsoft-IIS" >< banner || ( "Apache" >< banner && ( "(Win32)" >< banner || "(Win64)" >< banner ) ) ) {
    register_and_report_os( os:"Microsoft Windows", cpe:"cpe:/o:microsoft:windows", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"windows" );
    exit( 0 );
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

    if( "(Debian)" >< banner || "(Debian GNU/Linux)" >< banner || "devel-debian" >< banner || "~dotdeb+" >< banner ) {
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
      register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
      exit( 0 );
    }
  }

  if( "Nginx on Linux Debian" >< banner ) {
    register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }

  if( "ZNC" >< banner && ( "~bpo" >< banner || "+deb" >< banner ) ) {
    register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
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
    register_and_report_os( os:"Linux", cpe:"cpe:/o:linux:kernel", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
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

phpList = get_kb_list( "www/" + port + "/content/extensions/php" );
if( phpList ) phpFiles = make_list( phpList );
phpinfoBanner = get_kb_item( "php/phpinfo/phpversion/" + port );

if( phpFiles[0] ) {
  banner = get_http_banner( port:port, file:phpFiles[0] );
} else {
  banner = get_http_banner( port:port, file:"/index.php" );
}

if( banner && banner = egrep( pattern:"^X-Powered-By: PHP/(.*)$", string:banner, icase:TRUE ) ) {

  banner_type = "PHP Server banner";

  if( "+deb" >< banner || "~dotdeb+" >< banner || "~deb" >< banner ) {
    if( "+deb6" >< banner || "~deb6" >< banner || "~dotdeb+squeeze" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"6.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else if( "+deb7" >< banner || "~dotdeb+7" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"7.0", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else if ( "+deb8" >< banner || "~dotdeb+8" >< banner ) {
      register_and_report_os( os:"Debian GNU/Linux", version:"8", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    } else {
      register_and_report_os( os:"Debian GNU/Linux", cpe:"cpe:/o:debian:debian_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    }
    exit( 0 );
  }
  if( "ubuntu" >< banner ) {
    register_and_report_os( os:"Ubuntu", cpe:"cpe:/o:canonical:ubuntu_linux", banner_type:banner_type, port:port, banner:banner, desc:SCRIPT_DESC, runs_key:"unixoide" );
    exit( 0 );
  }
  register_unknown_os_banner( banner:banner, banner_type_name:banner_type, banner_type_short:"php_banner", port:port );
}

buf = http_get_cache( item:"/", port:port );
if( ! buf || buf !~ "HTTP/1.. 200" ) exit( 0 );

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

exit( 0 );