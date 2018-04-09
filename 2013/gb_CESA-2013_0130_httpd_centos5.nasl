###############################################################################
# OpenVAS Vulnerability Test
#
# CentOS Update for httpd CESA-2013:0130 centos5 
#
# Authors:
# System Generated Check
#
# Copyright:
# Copyright (c) 2013 Greenbone Networks GmbH, http://www.greenbone.net
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

include("revisions-lib.inc");
tag_insight = "The httpd packages contain the Apache HTTP Server (httpd), which is the
  namesake project of The Apache Software Foundation.

  Input sanitization flaws were found in the mod_negotiation module. A remote
  attacker able to upload or create files with arbitrary names in a directory
  that has the MultiViews options enabled, could use these flaws to conduct
  cross-site scripting and HTTP response splitting attacks against users
  visiting the site. (CVE-2008-0455, CVE-2008-0456, CVE-2012-2687)
  
  Bug fixes:
  
  * Previously, no check was made to see if the
  /etc/pki/tls/private/localhost.key file was a valid key prior to running
  the &quot;%post&quot; script for the &quot;mod_ssl&quot; package. Consequently, when
  /etc/pki/tls/certs/localhost.crt did not exist and &quot;localhost.key&quot; was
  present but invalid, upgrading the Apache HTTP Server daemon (httpd) with
  mod_ssl failed. The &quot;%post&quot; script has been fixed to test for an existing
  SSL key. As a result, upgrading httpd with mod_ssl now proceeds as
  expected. (BZ#752618)
  
  * The &quot;mod_ssl&quot; module did not support operation under FIPS mode.
  Consequently, when operating Red Hat Enterprise Linux 5 with FIPS mode
  enabled, httpd failed to start. An upstream patch has been applied to
  disable non-FIPS functionality if operating under FIPS mode and httpd now
  starts as expected. (BZ#773473)
  
  * Prior to this update, httpd exit status codes were not Linux Standard
  Base (LSB) compliant. When the command &quot;service httpd reload&quot; was run and
  httpd failed, the exit status code returned was &quot;0&quot; and not in the range 1
  to 6 as expected. A patch has been applied to the init script and httpd now
  returns &quot;1&quot; as an exit status code. (BZ#783242)
  
  * Chunked Transfer Coding is described in RFC 2616. Previously, the
  Apache server did not correctly handle a chunked encoded POST request with
  a &quot;chunk-size&quot; or &quot;chunk-extension&quot; value of 32 bytes or more.
  Consequently, when such a POST request was made the server did not respond.
  An upstream patch has been applied and the problem no longer occurs.
  (BZ#840845)
  
  * Due to a regression, when mod_cache received a non-cacheable 304
  response, the headers were served incorrectly. Consequently, compressed
  data could be returned to the client without the cached headers to indicate
  the data was compressed. An upstream patch has been applied to merge
  response and cached headers before data from the cache is served to the
  client. As a result, cached data is now correctly interpreted by the
  client. (BZ ... 

  Description truncated, for more information please check the Reference URL";


tag_affected = "httpd on CentOS 5";
tag_solution = "Please Install the Updated Packages.";



if(description)
{
  script_xref(name : "URL" , value : "http://lists.centos.org/pipermail/centos-announce/2013-January/019175.html");
  script_oid("1.3.6.1.4.1.25623.1.0.881569");
  script_version("$Revision: 9372 $");
  script_tag(name:"last_modification", value:"$Date: 2018-04-06 10:56:37 +0200 (Fri, 06 Apr 2018) $");
  script_tag(name:"creation_date", value:"2013-01-21 09:41:31 +0530 (Mon, 21 Jan 2013)");
  script_cve_id("CVE-2008-0455", "CVE-2008-0456", "CVE-2012-2687");
  script_tag(name:"cvss_base", value:"4.3");
  script_tag(name:"cvss_base_vector", value:"AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_xref(name: "CESA", value: "2013:0130");
  script_name("CentOS Update for httpd CESA-2013:0130 centos5 ");

  script_tag(name:"summary", value:"Check for the Version of httpd");
  script_category(ACT_GATHER_INFO);
  script_copyright("Copyright (c) 2013 Greenbone Networks GmbH");
  script_family("CentOS Local Security Checks");
  script_dependencies("gather-package-list.nasl");
  script_mandatory_keys("ssh/login/centos", "ssh/login/rpms");
  script_tag(name : "affected" , value : tag_affected);
  script_tag(name : "solution" , value : tag_solution);
  script_tag(name : "insight" , value : tag_insight);
  script_tag(name:"qod_type", value:"package");
  script_tag(name:"solution_type", value:"VendorFix");
  exit(0);
}


include("pkg-lib-rpm.inc");

release = get_kb_item("ssh/login/release");

res = "";
if(release == NULL){
  exit(0);
}

if(release == "CentOS5")
{

  if ((res = isrpmvuln(pkg:"httpd", rpm:"httpd~2.2.3~74.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-devel", rpm:"httpd-devel~2.2.3~74.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"httpd-manual", rpm:"httpd-manual~2.2.3~74.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if ((res = isrpmvuln(pkg:"mod_ssl", rpm:"mod_ssl~2.2.3~74.el5.centos", rls:"CentOS5")) != NULL)
  {
    security_message(data:res);
    exit(0);
  }

  if (__pkg_match) exit(99); # Not vulnerable.
  exit(0);
}
