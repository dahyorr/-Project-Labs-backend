import {
  createParamDecorator,
  ExecutionContext
} from '@nestjs/common'

export const Cookies = createParamDecorator((data: string, context: ExecutionContext) => {
  const request = context.switchToHttp().getRequest()
  return request.cookie
})