using identitynew.Models;
using Microsoft.EntityFrameworkCore.Storage;

namespace identitynew.Interfaces
{
    public interface IUnitOfWork : IDisposable
    {
        IRepository<T> Repository<T>() where T : BaseEntity;
        Task<int> CommitAsync();
        Task<IDbContextTransaction> BeginTransactionAsync();
    }

}
