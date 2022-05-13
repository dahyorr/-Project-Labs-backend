import {Request} from 'express'

export const cookieExtractor = function(req: Request, key?: string) {
  if (!req.cookies){
      return null
  }
  const value = req.cookies[key]
  return key ? value : req.cookies;
};