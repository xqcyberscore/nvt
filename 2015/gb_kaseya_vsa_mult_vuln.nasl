###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_kaseya_vsa_mult_vuln.nasl 2676 2016-02-17 09:05:41Z benallard $
#
# Kaseya Virtual System Administrator Multiple Vulnerabilities
#
# Authors:
# Shakeel <bshakeel@secpod.com>
#
# Copyright:
# Copyright (C) 2015 Greenbone Networks GmbH http://www.greenbone.net
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
###############################################################################

if (description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.805927");
  script_version("$Revision: 2676 $");
  script_cve_id("CVE-2015-2862", "CVE-2015-2863");
  script_bugtraq_id(75727, 75730);
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2016-02-17 10:05:41 +0100 (Wed, 17 Feb 2016) $");
  script_tag(name:"creation_date", value:"2015-07-17 11:50:12 +0530 (Fri, 17 Jul 2015)");
  script_name("Kaseya Virtual System Administrator Multiple Vulnerabilities");

  script_tag(name: "summary" , value:"The host is installed with Kaseya Virtual
  System Administrator and is prone to multiple vulnerabilities.");

  script_tag(name: "vuldetect" , value:"Send a crafted HTTP GET request and check
  whether it redirects to the malicious websites.");

  script_tag(name: "insight" , value:"Multiple errors exists due to improper
  validation of input passed via 'urlToLoad' GET Parameter to supportLoad.asp
  script and 'filepath' GET Parameter to Downloader.ashx script.");

  script_tag(name: "impact" , value:"Successful exploitation will allow remote
  attackers to download any arbitrary file, and create a specially crafted URL,
  that if clicked, would redirect  a victim from the intended legitimate web site
  to an arbitrary web site of the attacker's choosing.

  Impact Level: System/Application");

  script_tag(name: "affected" , value:"Kaseya Virtual System Administrator
  versions 7.x before patch level 7.0.0.29, 8.x before patch level 8.0.0.18,
  9.x before patch level 9.0.0.14 and 9.1.x before patch level 9.1.0.4");

  script_tag(name: "solution" , value:"Upgrade Kaseya Virtual System Administrator
  to patch level 7.0.0.29 or 8.0.0.18 or 9.0.0.14 or 9.1.0.4 or later. For updates
  refer http://www.kaseya.com");

  script_tag(name:"solution_type", value:"VendorFix");

  script_tag(name:"qod_type", value:"exploit");

  script_xref(name : "URL" , value : "https://www.kb.cert.org/vuls/id/919604");
  script_xref(name : "URL" , value : "https://www.exploit-db.com/exploits/37621");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/535996");
  script_xref(name : "URL" , value : "http://seclists.org/fulldisclosure/2015/Jul/63");
  script_xref(name : "URL" , value : "https://raw.githubusercontent.com/pedrib/PoC/master/generic/kaseya-vsa-vuln.txt");

  script_summary("Check if Kaseya Virtual System Administrator is vulnerable to open redirect");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2015 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

## Variable Initialization
url = "";
sndReq = "";
rcvRes = "";
vsaPort = "";

## Get HTTP Port
vsaPort = get_http_port(default:80);
if(!vsaPort){
  vsaPort = 80;
}

## Check Port State
if(!get_port_state(vsaPort)){
  exit(0);
}

## Iterate over possible paths
foreach dir (make_list_unique("/", "/kaseyavsa", "/vsa", cgi_dirs()))
{
  if( dir == "/" ) dir = "";

  ## Construct GET Request
  sndReq = http_get(item: string(dir + "/vsapres/web20/core/login.aspx"), port:vsaPort);
  rcvRes = http_keepalive_send_recv(port:vsaPort, data:sndReq);

  ##Confirm Application
  if(rcvRes && rcvRes =~ ">Copyright.*>Kaseya")
  {
    ##Construct Attack URL
    url = dir + "/inc/supportLoad.asp?urlToLoad=http://www.example.com";

    if(http_vuln_check(port:vsaPort, url:url, pattern:"(l|L)ocation.*http://www.example.com",
                       extra_check:">Please wait"))
    {
      security_message(vsaPort);
      exit(0);
    }
  }
}
