# OpenVAS Vulnerability Test
# $Id: deb_3120.nasl 9355 2018-04-06 07:16:07Z cfischer $
# Auto-generated from advisory DSA 3120-1 using nvtgen 1.0
# Script version: 1.0
#
# Author:
# Greenbone Networks
#
# Copyright:
# Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net
# Text descriptions are largely excerpted from the referenced
# advisory, and are Copyright (c) the respective author(s)
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation; either version 2
# of the License, or (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA.
#


if(description)
{
    script_oid("1.3.6.1.4.1.25623.1.0.703120");
    script_version("$Revision: 9355 $");
    script_cve_id("CVE-2013-1811", "CVE-2013-1934", "CVE-2013-4460", "CVE-2014-6316",
                  "CVE-2014-6387", "CVE-2014-7146", "CVE-2014-8553", "CVE-2014-8554",
                  "CVE-2014-8598", "CVE-2014-8986", "CVE-2014-8988", "CVE-2014-9089",
                  "CVE-2014-9117", "CVE-2014-9269", "CVE-2014-9270", "CVE-2014-9271",
                  "CVE-2014-9272", "CVE-2014-9280", "CVE-2014-9281", "CVE-2014-9388",
                  "CVE-2014-9506");
    script_name("Debian Security Advisory DSA 3120-1 (mantis - security update)");
    script_tag(name: "last_modification", value: "$Date: 2018-04-06 09:16:07 +0200 (Fri, 06 Apr 2018) $");
    script_tag(name: "creation_date", value: "2015-01-06 00:00:00 +0100 (Tue, 06 Jan 2015)");
    script_tag(name: "cvss_base", value: "10.0");
    script_tag(name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C");
    script_tag(name: "solution_type", value: "VendorFix");

    script_xref(name: "URL", value: "http://www.debian.org/security/2015/dsa-3120.html");


    script_category(ACT_GATHER_INFO);

    script_copyright("Copyright (c) 2015 Greenbone Networks GmbH http://greenbone.net");
    script_family("Debian Local Security Checks");
    script_dependencies("gather-package-list.nasl");
    script_mandatory_keys("ssh/login/debian_linux", "ssh/login/packages");
    script_tag(name: "affected",  value: "mantis on Debian Linux");
    script_tag(name: "insight",   value: "Mantis is an issue tracker that is
implemented in PHP. The main features include:

* Web Based
* Supports any platform that runs PHP
* Available in 68 localizations
* Customizable Issue Pages
* Multiple Projects per instance
* Support for Projects, Sub-Projects, and Categories.
* Users can have a different access level per project
* Changelog Support
* Roadmap
* User View Page
* Search and Filter
* Built-in Reporting (reports / graphs)
* Time Tracking
* Custom Fields
* Email notifications
* Users can monitor specific issues
* Attachments
* Issue Change History
* RSS Feeds
* Customizable issue workflow
* Sponsorships Support
* Export to csv, Microsoft Excel, Microsoft Word
* No limit on the number of users, issues, or projects.
* Public / Private Projects
* Public / Private Notes
* Public / Private Issues
* Public / Private News
* Issue Relationships
* Authentication
+ Default Mantis Authentication (recommended)
+ LDAP Integration
+ HTTP Basic Authentication Support
+ Active Directory Integration (patches available)
* Multi-DBMS Support (using ADODB)
+ MySQL
+ MS SQL
+ PostgreSQL
+ Oracle (experimental)
* Webservice (SOAP) interface
* and more");
    script_tag(name: "solution",  value: "For the stable distribution (wheezy),
these problems have been fixed in version 1.2.18-1.

We recommend that you upgrade your mantis packages.");
    script_tag(name: "summary",   value: "Multiple security issues have been
found in the Mantis bug tracking system, which may result in phishing, information
disclosure, CAPTCHA bypass, SQL injection, cross-site scripting or the execution of
arbitrary PHP code.");
    script_tag(name: "vuldetect", value: "This check tests the installed software version using the apt package manager.");
    script_tag(name:"qod_type", value:"package");
    exit(0);
}

include("revisions-lib.inc");
include("pkg-lib-deb.inc");

res = "";
report = "";
if ((res = isdpkgvuln(pkg:"mantis", ver:"1.2.18-1", rls_regex:"DEB7.[0-9]")) != NULL) {
    report += res;
}

if (report != "") {
    security_message(data:report);
} else if (__pkg_match) {
    exit(99); # Not vulnerable.
}
