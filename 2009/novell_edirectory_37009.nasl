###############################################################################
# OpenVAS Vulnerability Test
# $Id: novell_edirectory_37009.nasl 5190 2017-02-03 11:52:51Z cfi $
#
# Novell eDirectory '/dhost/modules?I:' Buffer Overflow Vulnerability
#
# Authors:
# Michael Meyer <michael.meyer@greenbone.net>
#
# Copyright:
# Copyright (c) 2009 Greenbone Networks GmbH
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
###############################################################################

CPE = "cpe:/a:novell:edirectory";

if(description)
{
  script_oid("1.3.6.1.4.1.25623.1.0.100343");
  script_version("$Revision: 5190 $");
  script_tag(name:"last_modification", value:"$Date: 2017-02-03 12:52:51 +0100 (Fri, 03 Feb 2017) $");
  script_tag(name:"creation_date", value:"2009-11-13 12:21:24 +0100 (Fri, 13 Nov 2009)");
  script_tag(name:"cvss_base", value:"9.0");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cve_id("CVE-2009-4653");
  script_bugtraq_id(37009);
  script_name("Novell eDirectory '/dhost/modules?I:' Buffer Overflow Vulnerability");
  script_category(ACT_GATHER_INFO);
  script_family("Buffer overflow");
  script_copyright("This script is Copyright (C) 2009 Greenbone Networks GmbH");
  script_dependencies("novell_edirectory_detect.nasl");
  script_require_ports("Services/ldap", 389, 636);
  script_mandatory_keys("eDirectory/installed");

  script_xref(name:"URL", value:"http://www.securityfocus.com/bid/37009");
  script_xref(name:"URL", value:"http://www.novell.com/products/edirectory/");
  script_xref(name:"URL", value:"http://www.securityfocus.com/archive/1/507812");

  tag_summary = "Novell eDirectory is prone to a buffer-overflow vulnerability
  because it fails to perform adequate boundary checks on user-supplied data.";

  tag_impact = "Attackers can exploit this issue to execute arbitrary code in the
  context of the affected application. Failed exploit attempts will
  likely cause denial-of-service conditions.";

  tag_affected = "Novell eDirectory 8.8 SP5 is vulnerable; other versions may also
  be affected.";

  script_tag(name:"summary", value:tag_summary);
  script_tag(name:"impact", value:tag_impact);
  script_tag(name:"affected", value:tag_affected);

  script_tag(name:"qod_type", value:"remote_banner");

  exit(0);
}

include("host_details.inc");

if( ! port = get_app_port( cpe:CPE ) ) exit( 0 );
if( ! get_app_version( cpe:CPE, port:port ) ) exit( 0 );

if(!version = get_kb_item(string("ldap/", port, "/eDirectory")))exit(0);
if(!isnull(version)) {

  versions = split(version,sep: " ", keep:FALSE);

  if(!isnull(versions[0])) {
     major = versions[0];
  } else {
     exit(0);
  }  

  if(!isnull(versions[1])) {
     if("SP" >< versions[1]) {
       sp = versions[1];
       sp -= "SP";
       sp = int(sp);
     } else {
       revision = versions[1];
     }   
  }

  if(sp && !isnull(versions[2])) {
     revision = versions[2];
  }  

  if(revision) {
   revision -= "(";
   revision -= ")";
   revision -= ".";
   revision = int(revision);
  }

   if(major == "8.8") { 
     if(sp && sp > 0) {
       if(sp == 5) { 
         if(!revision) {
           VULN = TRUE;
         }  
       }
       if(sp < 5 ) { 
         VULN = TRUE;
       }
     } else {
       VULN = TRUE;
     }
   }  
   else if(major == "8.8.1") {
       VULN = TRUE;
   }
   else if(major == "8.8.2") {
    if(!revision && !sp) {
       VULN = TRUE;
    }  
  }   
}

if(VULN) {
   security_message(port:port);
   exit(0);
}

exit(99);
