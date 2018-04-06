###############################################################################
# OpenVAS Vulnerability Test
# $Id: gb_ibm_web_experience_factory_xss_vuln.nasl 9352 2018-04-06 07:13:02Z cfischer $
#
# IBM Web Experience Factory Multiple Cross Site Scripting Vulnerabilities
#
# Authors:
# Madhuri D <dmadhuri@secpod.com>
#
# Copyright:
# Copyright (c) 2012 Greenbone Networks GmbH, http://www.greenbone.net
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

tag_impact = "Successful exploitation could allow remote attackers to execute arbitrary
  HTML and script code in a user's browser session in context of an affected
  site.
  Impact Level: Application";
tag_affected = "IBM Web Experience Factory version 7.0 and 7.0.1";

tag_insight = "The flaws are due to improper validation of user-supplied input to
  'INPUT' and 'TEXTAREA' elements.";
tag_solution = "Upgrade to the IBM Web Experience Factory 7.0.1.2 or later
  For updates refer to http://www14.software.ibm.com/webapp/download/home.jsp";
tag_summary = "This host is installed with IBM Web Experience Factory and is prone
  to multiple cross site scripting vulnerabilities.";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.802563");
  script_version("$Revision: 9352 $");
  script_bugtraq_id(51246);
  script_cve_id("CVE-2011-5048");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:13:02 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2012-01-19 18:01:09 +0530 (Thu, 19 Jan 2012)");
  script_name("IBM Web Experience Factory Multiple Cross Site Scripting Vulnerabilities");
  script_xref(name : "URL" , value : "http://www.securityfocus.com/bid/51246/info");
  script_xref(name : "URL" , value : "http://www-01.ibm.com/support/docview.wss?uid=swg21575083");

  script_tag(name:"qod_type", value:"registry");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2012 Greenbone Networks GmbH");
  script_family("General");
  script_dependencies("secpod_reg_enum.nasl");
  script_mandatory_keys("SMB/WindowsVersion");
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "summary" , value : tag_summary);
  script_tag(name : "impact" , value : tag_impact);
  script_tag(name : "affected" , value : tag_affected);
  exit(0);
}


include("smb_nt.inc");
include("version_func.inc");
include("secpod_smb_func.inc");

if(!get_kb_item("SMB/WindowsVersion")){
  exit(0);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\IBM WebSphere Portlet Factory";
if(!registry_key_exists(key:key)){
  exit(0);
}

## Check for DisplayName
ibmName = registry_get_sz(key:key, item:"DisplayName");
if("IBM WebSphere Portlet Factory" >< ibmName)
{
  ## Get the version from registry
  ibmVer = registry_get_sz(key:key + item, item:"DisplayVersion");

  if(ibmVer != NULL)
  {
    ## Check for IBM WebSphere Portlet Factory
    if(version_in_range(version:ibmVer, test_version:"7.0", test_version2:"7.0.1.0")){
      security_message(0) ;
    }
  }
}
