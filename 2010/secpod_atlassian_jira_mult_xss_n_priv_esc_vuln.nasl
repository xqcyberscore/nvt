###############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_atlassian_jira_mult_xss_n_priv_esc_vuln.nasl 5394 2017-02-22 09:22:42Z teissa $
#
# Atlassian JIRA Privilege Escalation and Multiple Cross Site Scripting Vulnerabilities
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

CPE = 'cpe:/a:atlassian:jira';

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.902047");
  script_version("$Revision: 5394 $");
  script_tag(name: "last_modification", value: "$Date: 2017-02-22 10:22:42 +0100 (Wed, 22 Feb 2017) $");
  script_tag(name: "creation_date", value: "2010-04-30 15:20:35 +0200 (Fri, 30 Apr 2010)");
  script_tag(name: "cvss_base", value: "9.0");
  script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C");

  script_bugtraq_id(39485);

  script_cve_id("CVE-2010-1164", "CVE-2010-1165");

  script_tag(name:"qod_type", value:"remote_banner");

  script_tag(name: "solution_type", value: "VendorFix");

  script_name("Atlassian JIRA Privilege Escalation and Multiple Cross Site Scripting Vulnerabilities");

  script_category(ACT_GATHER_INFO);

  script_copyright("Copyright (c) 2010 SecPod");
  script_family("Web application abuses");
  script_dependencies("secpod_atlassian_jira_detect.nasl");
  script_mandatory_keys("atlassian_jira/installed");

  script_tag(name: "summary", value: "Atlassian JIRA is prone to privilege escalation and multiple cross
site scripting vulnerabilities.");

  script_tag(name: "vuldetect", value: "Checks the version.");

  script_tag(name: "insight", value: "The flaws are caused because input passed to the
   - 'element' or 'defaultColor' parameters to the 'Colour Picker' page,
   - 'formName' and 'element' parameters and the 'full user name' field to the
     'User Picker' and 'Group Picker' page,
   - 'announcement_preview_banner_st' parameter to the 'Announcement Banner Preview' page,
   - 'portletKey' parameter to 'runportleterror.jsp',
      URL to 'issuelinksmall.jsp',
   - 'afterURL' parameter to 'screenshot-redirecter.jsp',
   - 'Referrer' HTTP request header to '500page.jsp'
   - 'groupnames.jsp', 'indexbrowser.jsp', 'classpath-debug.jsp',
     'viewdocument.jsp', and 'cleancommentspam.jsp'
  are not properly sanitised before being returned to the user.

  It allows administrative users to change certain path settings, which can be
  exploited to gain operating system account privileges to the server
  infrastructure.");

  script_tag(name: "impact", value: "Successful exploitation will let attackers to execute arbitrary script or
  gain higher privileges.
  Impact Level: Application");

  script_tag(name: "affected", value: "Atlassian JIRA version 3.12 through 4.1");

  script_tag(name: "solution", value: "Upgrade to the Atlassian JIRA version 4.1.1 or later or apply patch.
  For more details refer, http://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2010-04-16#JIRASecurityAdvisory2010-04-16-XSSVulnerabilitiesinJIRA");

  script_xref(name : "URL" , value : "http://secunia.com/advisories/39353");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57826");
  script_xref(name : "URL" , value : "http://xforce.iss.net/xforce/xfdb/57828");
  script_xref(name : "URL" , value : "http://jira.atlassian.com/browse/JRA-21004");
  script_xref(name : "URL" , value : "http://jira.atlassian.com/browse/JRA-20995");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/04/16/4");
  script_xref(name : "URL" , value : "http://www.openwall.com/lists/oss-security/2010/04/16/3");


  exit(0);
}

include("host_details.inc");
include("version_func.inc");

if (!port = get_app_port(cpe: CPE))
  exit(0);

if (!version = get_app_version(cpe: CPE, port: port))
  exit(0);

## Check for the version < 4.1.1
if (version_is_less(version: version, test_version: "4.1.1")) {
  report = report_fixed_ver(installed_version: version, fixed_version: "4.1.1");
  security_message(port: port, data: report);
  exit(0); 
}

exit(0);
