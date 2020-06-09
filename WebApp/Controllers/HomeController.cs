using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using Microsoft.AspNet.Identity;

namespace WebApp.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            ViewBag.Message = "Your application description page.";

            return View();
        }

        public ActionResult Contact()
        {
            ViewBag.Message = "Your contact page.";

            return View();
        }

        [Authorize]
        public ActionResult Claims()
        {
            ViewBag.Message = "Claims in Identity.";
            ViewBag.Username = User.Identity.GetUserName();
            ViewBag.UserId = User.Identity.GetUserId();
            ViewBag.Name = User.Identity.Name;
            return View();
        }

        public ActionResult Error(string message)
        {
            ViewBag.Message = message;

            return View("Error");
        }
    }
}