##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_free_php_blog_software_rfi_vuln.nasl 5394 2017-02-22 09:22:42Z teissa $
#
# FreePHPBlogSoftware 'default_theme.php' Remote File Inclusion Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
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
  script_oid("1.3.6.1.4.1.25623.1.0.902056");
  script_version("$Revision: 5394 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-22 10:22:42 +0100 (Wed, 22 Feb 2017) $");
  script_tag(name:"creation_date", value:"2010-05-28 16:52:49 +0200 (Fri, 28 May 2010)");
  script_cve_id("CVE-2010-1978");
  script_bugtraq_id(39233);
  script_tag(name:"cvss_base", value:"6.8");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_name("FreePHPBlogSoftware 'default_theme.php' Remote File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/39321");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57560");

  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("find_service.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  script_tag(name : "insight" , value : "The flaw is due to error an in 'default_theme.php' script, which
  fails to properly sanitize user input supplied to the 'phpincdir' parameter.");
  script_tag(name : "solution" , value : "No solution or patch was made available for at least one year
  since disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective
  features, remove the product or replace the product by another one.");
  script_tag(name : "summary" , value : "This host is running FreePHPBlogSoftware and is prone to remote
  file inclusion Vulnerability");
  script_tag(name : "impact" , value : "Successful exploitation will allow remote attackers to include
  arbitrary remote file containing malicious PHP code and execute it in the
  context of the webserver process.

  Impact Level: Application.");
  script_tag(name : "affected" , value : "FreePHPBlogSoftware version 1.0");

  script_tag(name:"solution_type", value:"WillNotFix");
  script_tag(name:"qod_type", value:"remote_banner");
  exit(0);
}


include("http_func.inc");
include("version_func.inc");
include("http_keepalive.inc");

## Get HTTP port
fpwsPort = get_http_port(default:80);

## Check the php support
if(!can_host_php(port:fpwsPort)){
  exit(0);
}

foreach dir (make_list_unique("/fpws", "/FPWS", "/", cgi_dirs(port:fpwsPort)))
{

  if(dir == "/") dir = "";

  ## Send and Receive the response
  rcvRes = http_get_cache(item: dir + "/index.php", port:fpwsPort);

  ## Confirm the application
  if (">FreePHPBlogSoftware<" >< rcvRes)
  {
    sndReq = http_get(item: dir + "/includes/themes_meta.inc", port:fpwsPort);
    rcvRes = http_keepalive_send_recv(port:fpwsPort, data:sndReq);

    ## Grep for the version
    fpwsVer = eregmatch(pattern:"Version: ([0-9.]+)" , string:rcvRes);
    if(fpwsVer[1] != NULL)
    {
      ## Check for FreePHPBlogSoftware version equal to 1.0
      if(version_is_equal(version:fpwsVer[1], test_version:"1.0")){
        security_message(port:fpwsPort);
        exit(0);
      }
    }
  }
}

exit(99);