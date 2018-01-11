###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_serendipity_sec_bypass_vuln.nasl 8362 2018-01-10 15:35:33Z cfischer $
#
# Serendipity 'Xinha WYSIWYG' Editor Security Bypass Vulnerability
#
# Authors:
# Antu Sanadi <santu@secpod.com>
#
# Copyright:
# Copyright (c) 2010 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation will allow attacker to bypass intended access
  restrictions and modify the configuration of arbitrary plugins.
  Impact Level: Application";
tag_affected = "Serendipity version 1.5.2 and on all platforms.";
tag_insight = "The flaw is due to an input validation error in 'Xinha WYSIWYG' editor with
  dynamic configuration feature enabled when processing the,
  - crafted 'backend_config_secret_key_location' and 'backend_config_hash'
     parameters that are used in a SHA1 hash of a shared secret that can be
     known or externally influenced, which are not properly handled by the
     'Deprecated config passing' feature.
  - crafted 'backend_data' and 'backend_data[key_location]' variables, which
     are not properly handled by the 'xinha_read_passed_data()' function.";
tag_solution = "Upgrade to Serendipity version 1.5.3 or later.
  For updates refer to http://www.s9y.org/12.html";
tag_summary = "This host is running Serendipity and is prone to security bypass
  vulnerability.";

CPE = "cpe:/a:s9y:serendipity";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.801337");
  script_version("$Revision: 8362 $");
  script_tag(name:"last_modification", value:"$Date: 2018-01-10 16:35:33 +0100 (Wed, 10 Jan 2018) $");
  script_tag(name:"creation_date", value:"2010-05-19 14:50:39 +0200 (Wed, 19 May 2010)");
  script_cve_id("CVE-2010-1916");
  script_tag(name:"cvss_base", value:"7.5");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_name("Serendipity 'Xinha WYSIWYG' Editor Security Bypass Vulnerability");
  script_xref(name : "URL" , value : "http://www.php-security.org/2010/05/10/mops-2010-020-xinha-wysiwyg-plugin-configuration-injection-vulnerability/index.html");
  script_xref(name : "URL" , value : "http://www.php-security.org/2010/05/10/mops-2010-019-serendipity-wysiwyg-editor-plugin-configuration-injection-vulnerability/index.html");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2010 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("serendipity_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Serendipity/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("host_details.inc");
include("version_func.inc");

if( ! serPort = get_app_port(cpe:CPE)) exit(0);

if( ! infos = get_app_version_and_location(cpe:CPE, port:serPort, exit_no_version:TRUE)) exit(0);
ver = infos['version'];
dir = infos['location'];

# Check for Serendipity version < 1.5.2
if(!isnull(ver) && (version_is_less_equal(version:ver, test_version:"1.5.2")))
{ 
  if((dir != NULL))
  { 
    # Confirm the 'Xinha WYSIWYG' editor installation
    sndReq = http_get(item:string(dir, "/htmlarea/examples/ExtendedDemo.html"),
                      port:serPort);
    rcvRes = http_send_recv(port:serPort, data:sndReq);
    if(">Xinha Extended Example<" >< rcvRes){
      security_message(serPort);
    }
  }
}
