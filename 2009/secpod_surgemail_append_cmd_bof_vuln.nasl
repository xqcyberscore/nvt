###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_surgemail_append_cmd_bof_vuln.nasl 7573 2017-10-26 09:18:50Z cfischer $
#
# SurgeMail 'APPEND' Command Buffer Overflow Vulnerability
#
# Authors:
# Sharath S <sharaths@secpod.com>
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

tag_impact = "Successful exploitation could allow remote authenticated users to cause a
  Denial of Service and possibly execute arbitrary code in the victim's system.
  Impact Level: Application";
tag_affected = "SurgeMail version prior to 3.9g2";
tag_insight = "Buffer overflow in the IMAP service is caused due the way it handles the
  APPEND command which can be exploited via a long first argument.";
tag_solution = "Upgrade to SurgeMail version 3.9g2 or later
  http://netwinsite.com/download.htm";
tag_summary = "This host is running SurgeMail and is prone to Buffer Overflow
  vulnerability.";

if(description)
{
  script_id(900840);
  script_version("$Revision: 7573 $");
  script_tag(name:"last_modification", value:"$Date: 2017-10-26 11:18:50 +0200 (Thu, 26 Oct 2017) $");
  script_tag(name:"creation_date", value:"2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)");
  script_tag(name:"cvss_base", value:"4.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_cve_id("CVE-2008-7182");
  script_bugtraq_id(30000);
  script_name("SurgeMail 'APPEND' Command Buffer Overflow Vulnerability");
  script_xref(name : "URL" , value : "http://secunia.com/advisories/30739/");
  script_xref(name : "URL" , value : "http://www.milw0rm.com/exploits/5968");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/archive/1/496482");
  script_xref(name : "URL" , value : "http://www.netwinsite.com/surgemail/help/updates.htm");

  script_tag(name:"qod_type", value:"remote_banner");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (C) 2009 SecPod");
  script_family("Denial of Service");
  script_dependencies("secpod_surgemail_detect.nasl");
  script_require_keys("SurgeMail/Ver");
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  exit(0);
}


include("http_func.inc");
include("version_func.inc");

# Grep for SurgeMail
surgemailVer = get_kb_item("SurgeMail/Ver");

if(!isnull(surgemailVer))
{
  # Check for SurgeMail version < 3.9g2
  if(version_is_less(version:surgemailVer, test_version:"3.9.g2")){
    security_message(port:0);
  }
}
