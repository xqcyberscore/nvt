##############################################################################
# OpenVAS Vulnerability Test
# $Id: secpod_novell_iprint_client_actvx_mult_vuln_900040.nasl 9349 2018-04-06 07:02:25Z cfischer $
# Description: Novell iPrint Client ActiveX Control Multiple Vulnerabilities
#
# Authors:
# Sharath S <sharaths@secpod.com>
#
# Copyright:
# Copyright (C) 2008 SecPod, http://www.secpod.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License version 2
# (or any later version), as published by the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
##############################################################################

tag_impact = "Remote exploitation could allow execution of arbitrary code to
        cause the server to crash or denying the access to legitimate users.
 Impact Level : Application";

tag_solution = "Upgrade to Novell iPrint Client version 5.40 or later,
 For updates refer to http://download.novell.com/index.jsp";

tag_affected = "Novell iPrint Client version 4.36 and prior on Windows (All).

 Affected Platform : Windows (Any).";

tag_insight = "The flaws are due to,
        - boundary errors in ienipp.ocx file when processing GetDriverFile(),
          GetFileList(), ExecuteRequest(), UploadPrinterDriver(),
          UploadResource(), UploadResource(), UploadResourceToRMS(),
          GetServerVersion(), GetResourceList(), or DeleteResource() methods.
        - a boundary error in nipplib.dll when processing IppGetDriverSettings()
          while creating a server reference or interpreting a URI.
        - an error in the GetFileList() method returns a list of images
          (eg., .jpg, .jpeg, .gif, and .bmp) in a directory specified as
          argument to the method.";


tag_summary = "This host has Novell iPrint Client installed, which is prone
 to activex control vulnerabilities.";


if(description)
{
 script_oid("1.3.6.1.4.1.25623.1.0.900040");
 script_version("$Revision: 9349 $");
 script_tag(name:"last_modification", value:"$Date: 2018-04-06 09:02:25 +0200 (Fri, 06 Apr 2018) $");
 script_tag(name:"creation_date", value:"2008-08-27 11:53:45 +0200 (Wed, 27 Aug 2008)");
 script_bugtraq_id(30813);
 script_cve_id("CVE-2008-2431",	"CVE-2008-2432");
 script_copyright("Copyright (C) 2008 SecPod");
 script_tag(name:"cvss_base", value:"9.3");
 script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_category(ACT_GATHER_INFO);
  script_tag(name:"qod_type", value:"registry");
 script_family("General");
 script_name("Novell iPrint Client ActiveX Control Multiple Vulnerabilities");
 script_dependencies("secpod_reg_enum.nasl");
 script_mandatory_keys("SMB/WindowsVersion");
 script_require_ports(139, 445);
 script_tag(name : "summary" , value : tag_summary);
 script_tag(name : "insight" , value : tag_insight);
 script_tag(name : "affected" , value : tag_affected);
 script_tag(name : "solution" , value : tag_solution);
 script_tag(name : "impact" , value : tag_impact);
 script_xref(name : "URL" , value : "http://www.frsirt.com/english/advisories/2008/2429");
 exit(0);
}


 include("smb_nt.inc");

 if(!get_kb_item("SMB/WindowsVersion")){
        exit(0);
 }

 iPrintVer = registry_get_sz(key:"SOFTWARE\Novell-iPrint",
			     item:"Current Version");
 if(!iPrintVer){
	exit(0);
 }

 if(ereg(pattern:"^v0?([0-3]\..*|4\.([0-2][0-9]|3[0-6])\.00)$",
	 string:iPrintVer)){
	 security_message(0);
 }
