using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Authentication_Demo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class SampleController : ControllerBase
    {
        [Authorize(Roles = "User")]
        //[AllowAnonymous]
        [HttpGet]
        public async Task<string> GetSampleData()
        {
            return "sample data from sample controller";
        }
    }
}
