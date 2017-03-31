###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_openfire_mult_vuln.nasl 4869 2016-12-29 11:01:45Z teissa $
#
# Ignite Realtime OpenFire Multiple Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Attacker may leverage this issue by executing arbitrary script code or
  injecting HTML or JavaScript code in the context of the affected system
  and can cause directory traversal or XSS attack.
  Impact Level: System";
tag_affected = "Ignite Realtime Openfire version prior to 3.6.3 on all platforms";
tag_insight = "Application fails to sanitise the user inputs in,
  - log parameter to logviewer.jsp and log.jsp files,
  - search parameter to group-summary.jsp file,
  - username parameter to user-properties.jsp file,
  - logDir, maxTotalSize, maxFileSize, maxDays, and logTimeout parameters
    to audit-policy.jsp file,
  - propName parameter to server-properties.jsp file, and
  - roomconfig_roomname and roomconfig_roomdesc parameters to
    muc-room-edit-form.jsp file.";
tag_solution = "Upgrade to OpenFire version 3.6.3
  http://www.igniterealtime.org/downloads/index.jsp";
tag_summary = "This host is running OpenFire and is prone to multiple
  vulnerabilities.";

if(description)
{
  script_id(800354);
  script_version("$Revision: 4869 $");
  script_tag(name:"last_modification", value:"$Date: 2016-12-29 12:01:45 +0100 (Thu, 29 Dec 2016) $");
  script_tag(name:"creation_date", value:"2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)");
  script_tag(name:"cvss_base", value:"5.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_cve_id("CVE-2009-0496", "CVE-2009-0497");
  script_bugtraq_id(32935, 32937, 32938, 32939, 32940, 32943, 32944, 32945);
  script_name("Ignite Realtime OpenFire Multiple Vulnerabilities");
  desc = "

  Summary:
  " + tag_summary + "

  Vulnerability Insight:
  " + tag_insight + "

  Impact:
  " + tag_impact + "

  Affected Software/OS:
  " + tag_affected + "

  Solution:
  " + tag_solution;
  script_xref(name : "URL" , value : "http://secunia.com/advisories/33452");
  script_xref(name : "URL" , value : "http://svn.igniterealtime.org/svn/repos/openfire/trunk/src/web/log.jsp");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/archive/1/499880/100/0/threaded");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 Greenbone Networks GmbH");
  script_family("Web application abuses");
  script_dependencies("gb_openfire_detect.nasl");
  script_require_ports("Services/www", 9090);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("version_func.inc");

firePort = get_kb_item("Services/www");
if(!firePort){
  exit(0);
}

fireVer = get_kb_item("www/" + firePort + "/Openfire");
if(fireVer != NULL)
{
  # Grep for Openfire version prior to 3.6.3
  if(version_is_less(version:fireVer, test_version:"3.6.3")){
    security_message(firePort);
  }
}
